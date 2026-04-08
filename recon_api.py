"""RECON//OS scan engine and helper utilities for the Django app."""

import asyncio
import functools
import html
import ipaddress
import json
import os
import re
import shutil
import socket
import sqlite3
import ssl
import subprocess
import tempfile
import threading
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, AsyncGenerator, Optional
from urllib import error as urllib_error
from urllib import parse as urllib_parse
from urllib import request as urllib_request

from pydantic import BaseModel


# Models

class ScanRequest(BaseModel):
    target: str
    modules: dict = {
        "subdomain": True,
        "port": True,
        "js": True,
        "dir": True,
        "dns": True,
        "fingerprint": True,
        "url_intel": True,
    }
    wordlist: Optional[str] = None
    ports: Optional[str] = None
    scan_mode: Optional[str] = "balanced"
    session_id: Optional[str] = None


# In-memory scan store  {scan_id: {status, results, errors}}
scans: dict = {}
scan_job_queue: Optional[asyncio.Queue[str]] = None
scan_workers_started = False
scan_worker_task: Optional[asyncio.Task[Any]] = None
scan_worker_loop: Optional[asyncio.AbstractEventLoop] = None
last_scan_times: dict[str, datetime] = {}
history_db_lock = threading.Lock()
history_db_connection: Optional[sqlite3.Connection] = None
history_db_backend = "file"


# Helpers

def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


@functools.lru_cache(maxsize=1)
def resolve_httpx_command() -> Optional[str]:
    """Return the ProjectDiscovery httpx binary if available."""
    candidate_paths = []
    direct_match = shutil.which("httpx")
    if direct_match:
        candidate_paths.append(direct_match)

    go_bin = Path.home() / "go" / "bin"
    for suffix in ("", ".exe", ".cmd", ".bat"):
        candidate_paths.append(str(go_bin / f"httpx{suffix}"))

    seen: set[str] = set()
    for candidate in candidate_paths:
        if not candidate or candidate in seen or not os.path.exists(candidate):
            continue
        seen.add(candidate)
        try:
            probe = subprocess.run(
                [candidate, "-h"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except Exception:
            continue

        help_text = f"{probe.stdout}\n{probe.stderr}".lower()
        if "-status-code" in help_text and ("-silent" in help_text or "projectdiscovery" in help_text):
            return candidate

    return None


HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)


def normalize_subdomain_candidate(raw_value: object, target: str) -> Optional[str]:
    text = re.sub(r"\x1b\[[0-9;]*m", "", str(raw_value or "")).strip().lower()
    if not text or any(ch.isspace() for ch in text):
        return None

    if text.startswith(("http://", "https://")):
        parsed = urllib_parse.urlsplit(text)
        text = parsed.netloc or parsed.path

    text = text.strip("[]").rstrip(".")
    if ":" in text and text.count(":") == 1:
        host_part, port_part = text.rsplit(":", 1)
        if port_part.isdigit():
            text = host_part

    if not text or len(text) > 253:
        return None

    if not text.endswith(f".{target}"):
        return None

    labels = text.split(".")
    if len(labels) < len(target.split(".")) + 1:
        return None

    if not all(HOST_LABEL_RE.fullmatch(label) for label in labels):
        return None

    return text


def filter_subdomain_candidates(candidates: list[str], target: str) -> tuple[list[str], int]:
    valid_candidates = []
    seen = set()
    ignored = 0

    for candidate in candidates:
        host = normalize_subdomain_candidate(candidate, target)
        if not host:
            if str(candidate or "").strip():
                ignored += 1
            continue
        if host in seen:
            continue
        seen.add(host)
        valid_candidates.append(host)

    return valid_candidates, ignored


def tool_status(name: str) -> bool:
    if name == "httpx":
        return resolve_httpx_command() is not None
    return tool_available(name)


def sse_event(data: dict) -> str:
    """Format a Server-Sent Event string."""
    return f"data: {json.dumps(data)}\n\n"


def normalize_target_input(raw_target: str) -> str:
    value = str(raw_target or "").strip().lower()
    if not value:
        return ""

    parsed = urllib_parse.urlsplit(value if "://" in value else f"//{value}")
    host = (parsed.netloc or parsed.path or "").strip().rstrip(".")
    if ":" in host and host.count(":") == 1:
        host_part, port_part = host.rsplit(":", 1)
        if port_part.isdigit():
            host = host_part
    return host


def merge_requested_modules(requested: Optional[dict]) -> dict:
    resolved = dict(DEFAULT_MODULES)
    if isinstance(requested, dict):
        resolved.update({key: bool(value) for key, value in requested.items()})
    return resolved


def target_is_allowed(target: str) -> bool:
    allowed = APP_SETTINGS["allowed_domains"]
    if not allowed:
        return True
    return any(target == domain or target.endswith(f".{domain}") for domain in allowed)


def target_is_ip_address(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def validate_target_scope(target: str) -> Optional[str]:
    if target_is_ip_address(target):
        return "Target must be a domain name, not a direct IP address"
    if "*" in target:
        return "Wildcard targets are not allowed. Enter a concrete hostname or domain."
    if not target_is_allowed(target):
        allowed = ", ".join(APP_SETTINGS["allowed_domains"])
        return f"Target is outside the configured allowlist: {allowed}"
    return None


def dashboard_path() -> Path:
    return Path(__file__).with_name("recon.html")


HISTORY_DB_PATH = Path(__file__).with_name("db.sqlite3")



def _get_django_saved_scan_model():
    if not env_flag("RECON_USE_DJANGO_ORM", False):
        return None
    try:
        from django.apps import apps

        if not apps.ready:
            return None
        return apps.get_model("reconweb", "SavedScan")
    except Exception:
        return None


def _record_from_model(instance) -> dict:
    return {
        "scan_id": instance.scan_id,
        "session_id": instance.session_id,
        "target": instance.target,
        "scan_mode": instance.scan_mode,
        "status": instance.status,
        "started_at": instance.started_at,
        "completed_at": instance.completed_at,
        "modules_enabled": instance.modules_enabled or {},
        "profile": instance.profile or {},
        "summary": instance.summary or {},
        "results": instance.results or {},
        "evidence": instance.evidence or [],
        "logs": instance.logs or [],
        "redaction_policy": instance.redaction_policy or "",
    }

DEFAULT_MODULES = {
    "subdomain": True,
    "port": True,
    "js": True,
    "dir": True,
    "dns": True,
    "fingerprint": True,
    "url_intel": True,
}


def env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    if value is None:
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def env_csv(name: str) -> list[str]:
    raw = os.environ.get(name, "")
    return [item.strip().lower() for item in raw.split(",") if item.strip()]


APP_SETTINGS = {
    "allowed_domains": env_csv("RECON_ALLOWED_DOMAINS"),
    "min_seconds_between_scans": max(0, int(os.environ.get("RECON_MIN_SECONDS_BETWEEN_SCANS", "3"))),
    "max_pending_jobs": max(1, int(os.environ.get("RECON_MAX_PENDING_JOBS", "10"))),
    "warn_on_wildcard_dns": env_flag("RECON_WARN_ON_WILDCARD_DNS", True),
}

SCAN_PROFILES = {
    "fast": {
        "subdomain_timeout": 18,
        "httpx_timeout": 10,
        "dns_timeout": 8,
        "port_timeout": 35,
        "fingerprint_timeout": 6,
        "gau_timeout": 8,
        "urlintel_timeout": 8,
        "js_page_limit": 1,
        "js_max_files": 6,
        "js_fetch_timeout": 3,
        "js_endpoint_limit": 20,
        "js_source_map_limit": 2,
        "dir_tool_timeout": 45,
        "dir_word_limit": 80,
        "dir_batch_size": 20,
        "dir_recursion_depth": 1,
        "dir_extensions": [".json", ".env"],
        "dir_similarity_tolerance": 32,
        "urlintel_max_urls": 40,
        "http_retries": 1,
        "http_backoff_base": 0.35,
        "ports": "80,443,8080,8443",
    },
    "balanced": {
        "subdomain_timeout": 35,
        "httpx_timeout": 20,
        "dns_timeout": 12,
        "port_timeout": 75,
        "fingerprint_timeout": 8,
        "gau_timeout": 12,
        "urlintel_timeout": 12,
        "js_page_limit": 2,
        "js_max_files": 12,
        "js_fetch_timeout": 4,
        "js_endpoint_limit": 40,
        "js_source_map_limit": 4,
        "dir_tool_timeout": 75,
        "dir_word_limit": 200,
        "dir_batch_size": 40,
        "dir_recursion_depth": 2,
        "dir_extensions": [".json", ".bak", ".zip", ".env"],
        "dir_similarity_tolerance": 48,
        "urlintel_max_urls": 80,
        "http_retries": 2,
        "http_backoff_base": 0.45,
        "ports": "21,22,25,53,80,443,3306,5432,6379,8080,8443,9200,27017",
    },
    "deep": {
        "subdomain_timeout": 60,
        "httpx_timeout": 30,
        "dns_timeout": 16,
        "port_timeout": 120,
        "fingerprint_timeout": 12,
        "gau_timeout": 20,
        "urlintel_timeout": 20,
        "js_page_limit": 4,
        "js_max_files": 25,
        "js_fetch_timeout": 6,
        "js_endpoint_limit": 80,
        "js_source_map_limit": 8,
        "dir_tool_timeout": 120,
        "dir_word_limit": 500,
        "dir_batch_size": 50,
        "dir_recursion_depth": 2,
        "dir_extensions": [".json", ".bak", ".zip", ".env", ".yaml", ".yml", ".sql", ".old"],
        "dir_similarity_tolerance": 64,
        "urlintel_max_urls": 140,
        "http_retries": 3,
        "http_backoff_base": 0.6,
        "ports": "21,22,25,53,80,110,143,443,445,993,995,1433,1521,2375,3000,3306,3389,5000,5432,5601,6379,7001,8080,8081,8443,8888,9090,9200,9300,11211,27017",
    },
}


def resolve_scan_profile(scan_mode: Optional[str], ports: Optional[str]) -> dict:
    normalized_mode = (scan_mode or "balanced").strip().lower()
    if normalized_mode not in SCAN_PROFILES:
        normalized_mode = "balanced"

    resolved = dict(SCAN_PROFILES[normalized_mode])
    resolved["mode"] = normalized_mode
    resolved["label"] = normalized_mode.upper()
    resolved["ports"] = (ports or resolved["ports"]).strip()
    return resolved


def profile_summary(profile: dict) -> dict:
    return {
        "mode": profile["mode"],
        "ports": profile["ports"],
        "js_max_files": profile["js_max_files"],
        "dir_word_limit": profile["dir_word_limit"],
        "urlintel_max_urls": profile["urlintel_max_urls"],
        "http_retries": profile["http_retries"],
    }


def _open_history_connection() -> sqlite3.Connection:
    global history_db_backend, history_db_connection

    if history_db_connection is None:
        try:
            conn = sqlite3.connect(HISTORY_DB_PATH, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=OFF")
            conn.execute("PRAGMA synchronous=OFF")
            conn.execute("PRAGMA temp_store=MEMORY")
        except sqlite3.Error as exc:
            try:
                conn.close()
            except Exception:
                pass
            raise RuntimeError(
                f"Persistent history database unavailable at {HISTORY_DB_PATH}"
            ) from exc
        history_db_connection = conn
        history_db_backend = "file"

    return history_db_connection


def get_db_connection(reset_if_needed: bool = False) -> sqlite3.Connection:
    try:
        return _open_history_connection()
    except sqlite3.OperationalError:
        if not reset_if_needed:
            raise
        return _open_history_connection()


def init_history_db() -> None:
    if _get_django_saved_scan_model() is not None:
        return
    with history_db_lock, get_db_connection(reset_if_needed=True) as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                scan_id TEXT PRIMARY KEY,
                session_id TEXT,
                target TEXT NOT NULL,
                scan_mode TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                modules_json TEXT NOT NULL,
                profile_json TEXT NOT NULL,
                summary_json TEXT,
                results_json TEXT,
                evidence_json TEXT,
                logs_json TEXT
            )
            """
        )


def deserialize_json(value: Optional[str], default):
    if not value:
        return default
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


def save_scan_record(record: dict) -> None:
    SavedScan = _get_django_saved_scan_model()
    if SavedScan is not None:
        try:
            SavedScan.objects.update_or_create(
                scan_id=record["scan_id"],
                defaults={
                    "session_id": record.get("session_id", ""),
                    "target": record["target"],
                    "scan_mode": record["scan_mode"],
                    "status": record["status"],
                    "started_at": record["started_at"],
                    "completed_at": record.get("completed_at"),
                    "modules_enabled": record.get("modules_enabled", {}),
                    "profile": record.get("profile", {}),
                    "summary": record.get("summary", {}),
                    "results": record.get("results", {}),
                    "evidence": record.get("evidence", []),
                    "logs": record.get("logs", []),
                    "redaction_policy": record.get("redaction_policy", ""),
                },
            )
            return
        except Exception:
            pass

    with history_db_lock, get_db_connection() as conn:
        conn.execute(
            """
            INSERT OR REPLACE INTO scans (
                scan_id,
                session_id,
                target,
                scan_mode,
                status,
                started_at,
                completed_at,
                modules_json,
                profile_json,
                summary_json,
                results_json,
                evidence_json,
                logs_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["scan_id"],
                record.get("session_id"),
                record["target"],
                record["scan_mode"],
                record["status"],
                record["started_at"],
                record.get("completed_at"),
                json.dumps(record.get("modules_enabled", {})),
                json.dumps(record.get("profile", {})),
                json.dumps(record.get("summary", {})),
                json.dumps(record.get("results", {})),
                json.dumps(record.get("evidence", [])),
                json.dumps(record.get("logs", [])),
            ),
        )


def list_scan_records(limit: int = 25) -> list[dict]:
    safe_limit = max(1, min(limit, 100))
    SavedScan = _get_django_saved_scan_model()
    if SavedScan is not None:
        try:
            rows = list(
                SavedScan.objects.order_by("-started_at").values(
                    "scan_id",
                    "session_id",
                    "target",
                    "scan_mode",
                    "status",
                    "started_at",
                    "completed_at",
                    "summary",
                )[:safe_limit]
            )
            return [
                {
                    "scan_id": row["scan_id"],
                    "session_id": row["session_id"],
                    "target": row["target"],
                    "scan_mode": row["scan_mode"],
                    "status": row["status"],
                    "started_at": row["started_at"],
                    "completed_at": row["completed_at"],
                    "summary": row.get("summary") or {},
                }
                for row in rows
            ]
        except Exception:
            pass

    with history_db_lock, get_db_connection() as conn:
        rows = conn.execute(
            """
            SELECT scan_id, session_id, target, scan_mode, status, started_at, completed_at, summary_json
            FROM scans
            ORDER BY started_at DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()

    items = []
    for row in rows:
        items.append(
            {
                "scan_id": row["scan_id"],
                "session_id": row["session_id"],
                "target": row["target"],
                "scan_mode": row["scan_mode"],
                "status": row["status"],
                "started_at": row["started_at"],
                "completed_at": row["completed_at"],
                "summary": deserialize_json(row["summary_json"], {}),
            }
        )
    return items


def get_scan_record(scan_id: str) -> Optional[dict]:
    SavedScan = _get_django_saved_scan_model()
    if SavedScan is not None:
        try:
            instance = SavedScan.objects.filter(scan_id=scan_id).first()
            if instance:
                return _record_from_model(instance)
        except Exception:
            pass

    with history_db_lock, get_db_connection() as conn:
        row = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()

    if not row:
        return None

    return {
        "scan_id": row["scan_id"],
        "session_id": row["session_id"],
        "target": row["target"],
        "scan_mode": row["scan_mode"],
        "status": row["status"],
        "started_at": row["started_at"],
        "completed_at": row["completed_at"],
        "modules_enabled": deserialize_json(row["modules_json"], {}),
        "profile": deserialize_json(row["profile_json"], {}),
        "summary": deserialize_json(row["summary_json"], {}),
        "results": deserialize_json(row["results_json"], {}),
        "evidence": deserialize_json(row["evidence_json"], []),
        "logs": deserialize_json(row["logs_json"], []),
    }


def build_saved_evidence(module: str, data: dict) -> dict:
    if module == "subdomain":
        return {
            "module": module,
            "main": f"{data.get('name', '?')} -> {str(data.get('status', 'unknown')).upper()}",
            "source": data.get("source", "unknown"),
            "detail": data.get("evidence") or f"{data.get('name', '?')} resolved to {data.get('ip', '-')}",
        }
    if module == "dns":
        return {
            "module": module,
            "main": f"{data.get('kind', 'dns')} {data.get('name', '?')} -> {data.get('value', '-')}",
            "source": data.get("source", "unknown"),
            "detail": data.get("evidence") or "dns record discovered",
        }
    if module == "port":
        return {
            "module": module,
            "main": f"Port {data.get('port', '?')}/{data.get('service', 'unknown')}",
            "source": data.get("source", "unknown"),
            "detail": data.get("evidence") or "Open port discovered",
        }
    if module == "fingerprint":
        return {
            "module": module,
            "main": f"{data.get('kind', 'fingerprint')} {data.get('name', '?')} -> {data.get('value', '-')}",
            "source": data.get("source", "unknown"),
            "detail": data.get("evidence") or "fingerprint signal collected",
        }
    if module == "js":
        return {
            "module": module,
            "main": f"{data.get('type', 'MATCH')} in {data.get('url', '-')}",
            "source": data.get("source", "unknown"),
            "detail": data.get("evidence") or data.get("detail", ""),
        }
    if module == "url_intel":
        return {
            "module": module,
            "main": f"{data.get('kind', 'url_intel')} {data.get('name', '?')}",
            "source": data.get("source", "unknown"),
            "detail": data.get("evidence") or data.get("value", ""),
        }
    if module == "dir":
        return {
            "module": module,
            "main": f"{data.get('path', '-')} [{data.get('code', '?')}]",
            "source": data.get("source", "unknown"),
            "detail": data.get("evidence") or "Directory probe match",
        }
    return {
        "module": module,
        "main": "Unknown evidence",
        "source": data.get("source", "unknown"),
        "detail": data.get("evidence", ""),
    }


def build_record_summary(record: dict) -> dict:
    results = record.get("results") or {}
    subdomains = results.get("subdomains") or []
    ports = results.get("ports") or []
    js_findings = results.get("js_findings") or []
    directories = results.get("directories") or []

    summary = dict(record.get("summary") or {})
    summary.setdefault("subdomains", len(subdomains))
    summary.setdefault("live_subdomains", sum(1 for item in subdomains if item.get("status") == "live"))
    summary.setdefault("dns_records", len(results.get("dns_records") or []))
    summary.setdefault("ports", len(ports))
    summary.setdefault("critical_ports", sum(1 for item in ports if item.get("critical")))
    summary.setdefault("fingerprints", len(results.get("fingerprints") or []))
    summary.setdefault("js_findings", len(js_findings))
    summary.setdefault("high_js_findings", sum(1 for item in js_findings if item.get("severity") in ("high", "critical")))
    summary.setdefault("js_scanned", 0)
    summary.setdefault("url_intel", len(results.get("url_intel") or []))
    summary.setdefault("dirs", len(directories))
    summary.setdefault("ok_dirs", sum(1 for item in directories if item.get("code") == 200))
    summary["exposed_keys"] = sum(1 for item in js_findings if finding_is_sensitive(str(item.get("type", ""))))
    return summary


def compare_item_key(module: str, data: dict) -> str:
    if module == "subdomains":
        return str(data.get("name", "")).lower()
    if module == "dns_records":
        return f"{str(data.get('kind', '')).lower()}|{str(data.get('name', '')).lower()}|{str(data.get('value', '')).lower()}"
    if module == "ports":
        return str(data.get("port", ""))
    if module == "fingerprints":
        return f"{str(data.get('kind', '')).lower()}|{str(data.get('name', '')).lower()}|{str(data.get('value', '')).lower()}"
    if module == "js_findings":
        return f"{str(data.get('type', '')).lower()}|{str(data.get('url', '')).lower()}"
    if module == "url_intel":
        return f"{str(data.get('kind', '')).lower()}|{str(data.get('name', '')).lower()}|{str(data.get('value', '')).lower()}"
    if module == "directories":
        return str(data.get("path", "")).lower()
    return json.dumps(data, sort_keys=True)


def compare_item_payload(module: str, data: dict) -> dict:
    if module == "subdomains":
        return {
            "status": data.get("status"),
            "ip": data.get("ip"),
            "code": data.get("code"),
            "source": data.get("source"),
        }
    if module == "ports":
        return {
            "service": data.get("service"),
            "critical": bool(data.get("critical")),
            "interesting": bool(data.get("interesting")),
            "source": data.get("source"),
        }
    if module == "dns_records":
        return {
            "kind": data.get("kind"),
            "value": data.get("value"),
            "source": data.get("source"),
        }
    if module == "fingerprints":
        return {
            "kind": data.get("kind"),
            "value": data.get("value"),
            "status_code": data.get("status_code"),
            "source": data.get("source"),
        }
    if module == "js_findings":
        return {
            "severity": data.get("severity"),
            "detail": data.get("detail"),
            "source": data.get("source"),
            "redacted": bool(data.get("redacted")),
        }
    if module == "url_intel":
        return {
            "kind": data.get("kind"),
            "name": data.get("name"),
            "value": data.get("value"),
            "source": data.get("source"),
        }
    if module == "directories":
        return {
            "code": data.get("code"),
            "size": data.get("size"),
            "source": data.get("source"),
        }
    return data


def format_compare_item(module: str, data: dict) -> dict:
    if module == "subdomains":
        parts = [str(data.get("status", "unknown")).upper()]
        if data.get("ip"):
            parts.append(str(data.get("ip")))
        if data.get("code") and str(data.get("code")) not in ("?", "-", "None"):
            parts.append(f"[{data.get('code')}]")
        return {
            "key": compare_item_key(module, data),
            "title": data.get("name", "?"),
            "summary": " | ".join(parts),
            "source": data.get("source", "unknown"),
        }
    if module == "ports":
        flags = []
        if data.get("critical"):
            flags.append("CRITICAL")
        elif data.get("interesting"):
            flags.append("INTERESTING")
        return {
            "key": compare_item_key(module, data),
            "title": f"{data.get('port', '?')}/{data.get('service', 'unknown')}",
            "summary": " | ".join(flags) if flags else "OPEN",
            "source": data.get("source", "unknown"),
        }
    if module == "dns_records":
        return {
            "key": compare_item_key(module, data),
            "title": f"{data.get('kind', 'DNS')} {data.get('name', '?')}",
            "summary": str(data.get("value", "-")),
            "source": data.get("source", "unknown"),
        }
    if module == "fingerprints":
        return {
            "key": compare_item_key(module, data),
            "title": f"{data.get('kind', 'FINGERPRINT')} {data.get('name', '?')}",
            "summary": str(data.get("value", "-")),
            "source": data.get("source", "unknown"),
        }
    if module == "js_findings":
        return {
            "key": compare_item_key(module, data),
            "title": f"{data.get('type', 'MATCH')} @ {data.get('url', '-')}",
            "summary": f"{str(data.get('severity', 'info')).upper()} | {data.get('detail', '')}",
            "source": data.get("source", "unknown"),
        }
    if module == "url_intel":
        return {
            "key": compare_item_key(module, data),
            "title": f"{data.get('kind', 'URL')} {data.get('name', '?')}",
            "summary": str(data.get("value", "-")),
            "source": data.get("source", "unknown"),
        }
    if module == "directories":
        return {
            "key": compare_item_key(module, data),
            "title": data.get("path", "-"),
            "summary": f"[{data.get('code', '?')}] {data.get('size', '-')}",
            "source": data.get("source", "unknown"),
        }
    return {
        "key": compare_item_key(module, data),
        "title": "Unknown",
        "summary": json.dumps(data, sort_keys=True),
        "source": data.get("source", "unknown"),
    }


def build_module_diff(module: str, left_items: list[dict], right_items: list[dict]) -> dict:
    left_map = {compare_item_key(module, item): item for item in left_items}
    right_map = {compare_item_key(module, item): item for item in right_items}
    left_keys = set(left_map)
    right_keys = set(right_map)

    added = [format_compare_item(module, right_map[key]) for key in sorted(right_keys - left_keys)]
    removed = [format_compare_item(module, left_map[key]) for key in sorted(left_keys - right_keys)]
    changed = []

    for key in sorted(left_keys & right_keys):
        left_item = left_map[key]
        right_item = right_map[key]
        if compare_item_payload(module, left_item) == compare_item_payload(module, right_item):
            continue
        changed.append(
            {
                "key": key,
                "title": format_compare_item(module, right_item)["title"],
                "before": format_compare_item(module, left_item),
                "after": format_compare_item(module, right_item),
            }
        )

    return {
        "left_count": len(left_items),
        "right_count": len(right_items),
        "added_count": len(added),
        "removed_count": len(removed),
        "changed_count": len(changed),
        "added": added,
        "removed": removed,
        "changed": changed,
    }


def build_compare_record(record: dict) -> dict:
    return {
        "scan_id": record["scan_id"],
        "session_id": record.get("session_id"),
        "target": record["target"],
        "scan_mode": record.get("scan_mode", "balanced"),
        "status": record.get("status", "completed"),
        "started_at": record.get("started_at"),
        "completed_at": record.get("completed_at"),
        "summary": build_record_summary(record),
    }


def build_summary_delta(left_record: dict, right_record: dict) -> dict:
    left_summary = build_record_summary(left_record)
    right_summary = build_record_summary(right_record)
    metrics = {}

    for key in (
        "subdomains",
        "live_subdomains",
        "ports",
        "dns_records",
        "fingerprints",
        "critical_ports",
        "js_findings",
        "high_js_findings",
        "js_scanned",
        "url_intel",
        "exposed_keys",
        "dirs",
        "ok_dirs",
    ):
        left_value = int(left_summary.get(key, 0) or 0)
        right_value = int(right_summary.get(key, 0) or 0)
        metrics[key] = {
            "left": left_value,
            "right": right_value,
            "delta": right_value - left_value,
        }

    return metrics


def build_history_compare(left_record: dict, right_record: dict) -> dict:
    left_results = left_record.get("results") or {}
    right_results = right_record.get("results") or {}

    return {
        "left": build_compare_record(left_record),
        "right": build_compare_record(right_record),
        "summary_delta": build_summary_delta(left_record, right_record),
        "modules": {
            "subdomains": build_module_diff(
                "subdomains",
                left_results.get("subdomains") or [],
                right_results.get("subdomains") or [],
            ),
            "dns_records": build_module_diff(
                "dns_records",
                left_results.get("dns_records") or [],
                right_results.get("dns_records") or [],
            ),
            "ports": build_module_diff(
                "ports",
                left_results.get("ports") or [],
                right_results.get("ports") or [],
            ),
            "fingerprints": build_module_diff(
                "fingerprints",
                left_results.get("fingerprints") or [],
                right_results.get("fingerprints") or [],
            ),
            "js_findings": build_module_diff(
                "js_findings",
                left_results.get("js_findings") or [],
                right_results.get("js_findings") or [],
            ),
            "url_intel": build_module_diff(
                "url_intel",
                left_results.get("url_intel") or [],
                right_results.get("url_intel") or [],
            ),
            "directories": build_module_diff(
                "directories",
                left_results.get("directories") or [],
                right_results.get("directories") or [],
            ),
        },
    }


init_history_db()


async def run_cmd(cmd: list[str], timeout: int = 120, input_data: Optional[bytes] = None) -> tuple[str, str, int]:
    """Run a subprocess in a worker thread and return (stdout, stderr, returncode)."""

    def _run() -> tuple[str, str, int]:
        try:
            completed = subprocess.run(
                cmd,
                input=input_data,
                capture_output=True,
                timeout=timeout,
                check=False,
            )
            return (
                completed.stdout.decode(errors="ignore"),
                completed.stderr.decode(errors="ignore"),
                completed.returncode,
            )
        except subprocess.TimeoutExpired:
            return "", "Timeout", -1
        except FileNotFoundError:
            return "", f"Command not found: {cmd[0]}", -1
        except Exception as exc:
            return "", str(exc), -1

    return await asyncio.to_thread(_run)


async def fetch_url_bytes(
    url: str,
    timeout: int = 8,
    max_bytes: Optional[int] = None,
    method: str = "GET",
    headers: Optional[dict[str, str]] = None,
    profile: Optional[dict] = None,
) -> tuple[bytes, dict[str, str], int, str]:
    """Fetch URL contents in a worker thread with retry/backoff support."""

    retry_count = max(1, int((profile or {}).get("http_retries", 1)))
    backoff_base = float((profile or {}).get("http_backoff_base", 0.35))
    request_headers = {"User-Agent": "Mozilla/5.0"}
    if headers:
        request_headers.update(headers)

    last_error = None
    for attempt in range(1, retry_count + 1):
        def _fetch() -> tuple[bytes, dict[str, str], int, str]:
            req = urllib_request.Request(url, headers=request_headers, method=method)
            with urllib_request.urlopen(req, timeout=timeout) as response:
                data = response.read(max_bytes) if max_bytes else response.read()
                return data, dict(response.headers.items()), int(response.status), str(response.geturl())

        try:
            return await asyncio.to_thread(_fetch)
        except urllib_error.HTTPError as exc:
            body = exc.read(max_bytes) if max_bytes else exc.read()
            return body, dict(exc.headers.items()), int(exc.code), url
        except Exception as exc:
            last_error = exc
            if attempt >= retry_count:
                raise
            await asyncio.sleep(backoff_base * attempt)

    raise last_error or RuntimeError("fetch failed")


async def fetch_url_text(
    url: str,
    timeout: int = 8,
    max_bytes: Optional[int] = None,
    method: str = "GET",
    headers: Optional[dict[str, str]] = None,
    profile: Optional[dict] = None,
) -> str:
    body, _, _, _ = await fetch_url_bytes(
        url,
        timeout=timeout,
        max_bytes=max_bytes,
        method=method,
        headers=headers,
        profile=profile,
    )
    return body.decode(errors="ignore")


SENSITIVE_FINDING_KEYWORDS = ("KEY", "SECRET", "TOKEN", "PASSWORD", "PRIVATE_KEY")


def finding_is_sensitive(finding_type: str) -> bool:
    return any(keyword in (finding_type or "") for keyword in SENSITIVE_FINDING_KEYWORDS)


def redact_sensitive_value(value: object) -> str:
    text = str(value or "").strip()
    if not text:
        return "[redacted]"

    if "PRIVATE KEY" in text:
        return "[private key redacted]"

    if len(text) <= 8:
        return "[redacted]"

    if len(text) <= 16:
        return f"{text[:2]}...{text[-2:]}"

    return f"{text[:4]}...{text[-4:]}"


DNS_SELECTORS = ("default", "google", "selector1", "selector2", "k1", "dkim")


async def query_nslookup(target: str, record_type: str, server: Optional[str] = None, timeout: int = 10) -> tuple[str, str, int]:
    cmd = ["nslookup", f"-type={record_type}", target]
    if server:
        cmd.append(server)
    return await run_cmd(cmd, timeout=timeout)


async def resolve_a_records(target: str) -> list[str]:
    records = set()

    try:
        info = await asyncio.to_thread(socket.getaddrinfo, target, None, socket.AF_INET)
        for entry in info:
            records.add(entry[4][0])
    except socket.gaierror:
        pass

    return sorted(records)


async def resolve_aaaa_records(target: str) -> list[str]:
    records = set()
    try:
        info = await asyncio.to_thread(socket.getaddrinfo, target, None, socket.AF_INET6)
        for entry in info:
            records.add(entry[4][0])
    except socket.gaierror:
        pass
    return sorted(records)


def parse_nslookup_records(record_type: str, stdout: str) -> list[dict]:
    results: list[dict] = []
    lines = [line.strip() for line in stdout.splitlines() if line.strip()]

    if record_type == "MX":
        for line in lines:
            match = re.search(r"mail exchanger = ([^\s]+)", line, re.IGNORECASE)
            pref_match = re.search(r"MX preference = (\d+)", line, re.IGNORECASE)
            if match:
                results.append({
                    "kind": "MX",
                    "value": match.group(1).rstrip("."),
                    "priority": int(pref_match.group(1)) if pref_match else None,
                    "raw": line,
                })
        return results

    if record_type == "NS":
        for line in lines:
            match = re.search(r"nameserver = ([^\s]+)", line, re.IGNORECASE)
            if match:
                results.append({"kind": "NS", "value": match.group(1).rstrip("."), "raw": line})
        return results

    if record_type == "TXT":
        text_matches = re.findall(r'text = "([^"]*)"', stdout, re.IGNORECASE)
        for value in text_matches:
            results.append({"kind": "TXT", "value": value, "raw": value})
        return results

    if record_type == "CNAME":
        for line in lines:
            match = re.search(r"canonical name = ([^\s]+)", line, re.IGNORECASE)
            if match:
                results.append({"kind": "CNAME", "value": match.group(1).rstrip("."), "raw": line})
        return results

    return results


async def detect_wildcard_dns(target: str) -> Optional[list[str]]:
    probe_host = f"wildcard-check-{uuid.uuid4().hex[:8]}.{target}"
    a_records = await resolve_a_records(probe_host)
    aaaa_records = await resolve_aaaa_records(probe_host)
    records = sorted(set(a_records + aaaa_records))
    return records or None


async def run_dns_recon(target: str, profile: dict) -> AsyncGenerator[dict, None]:
    yield {"module": "dns", "type": "log", "msg": f"Starting dns for {target}"}

    record_targets = [
        ("A", target),
        ("AAAA", target),
        ("MX", target),
        ("NS", target),
        ("TXT", target),
        ("CNAME", target),
        ("TXT", f"_dmarc.{target}"),
    ]
    total_steps = len(record_targets) + len(DNS_SELECTORS) + 2
    completed_steps = 0
    results: list[dict] = []
    ns_records: list[str] = []

    async def emit_progress() -> dict:
        pct = int((completed_steps / total_steps) * 100) if total_steps else 100
        return {"module": "dns", "type": "progress", "progress": min(100, pct)}

    a_records = await resolve_a_records(target)
    for record in a_records:
        entry = {"kind": "A", "name": target, "value": record, "source": "socket.getaddrinfo", "evidence": f"A {target} -> {record}"}
        results.append(entry)
        yield {"module": "dns", "type": "result", "data": entry, "msg": f"A {target} -> {record}", "level": "success"}
    completed_steps += 1
    yield await emit_progress()

    aaaa_records = await resolve_aaaa_records(target)
    for record in aaaa_records:
        entry = {"kind": "AAAA", "name": target, "value": record, "source": "socket.getaddrinfo", "evidence": f"AAAA {target} -> {record}"}
        results.append(entry)
        yield {"module": "dns", "type": "result", "data": entry, "msg": f"AAAA {target} -> {record}", "level": "success"}
    completed_steps += 1
    yield await emit_progress()

    for record_type, lookup_target in record_targets[2:]:
        stdout, stderr, rc = await query_nslookup(lookup_target, record_type, timeout=profile["dns_timeout"])
        parsed = parse_nslookup_records(record_type, stdout)
        if rc != 0 and not parsed:
            yield {"module": "dns", "type": "log", "msg": f"{record_type} lookup failed for {lookup_target}: {(stderr or 'no output')[:120]}", "level": "warn"}
        for item in parsed:
            kind = item["kind"]
            value = item["value"]
            if kind == "TXT" and lookup_target.startswith("_dmarc."):
                kind = "DMARC"
            elif kind == "TXT" and str(value).lower().startswith("v=spf1"):
                kind = "SPF"
            entry = {
                "kind": kind,
                "name": lookup_target,
                "value": value,
                "priority": item.get("priority"),
                "source": "nslookup",
                "evidence": item["raw"],
            }
            results.append(entry)
            if kind == "NS":
                ns_records.append(value)
            yield {"module": "dns", "type": "result", "data": entry, "msg": f"{kind} {lookup_target} -> {value}", "level": "success" if kind in {"SPF", "DMARC"} else ""}
        completed_steps += 1
        yield await emit_progress()

    for selector in DNS_SELECTORS:
        selector_name = f"{selector}._domainkey.{target}"
        stdout, _, _ = await query_nslookup(selector_name, "TXT", timeout=profile["dns_timeout"])
        parsed = parse_nslookup_records("TXT", stdout)
        if parsed:
            for item in parsed:
                entry = {
                    "kind": "DKIM",
                    "name": selector_name,
                    "value": item["value"],
                    "selector": selector,
                    "source": "nslookup",
                    "evidence": item["raw"],
                }
                results.append(entry)
                yield {"module": "dns", "type": "result", "data": entry, "msg": f"DKIM {selector_name} -> present", "level": "success"}
        completed_steps += 1
        yield await emit_progress()

    if ns_records:
        for nameserver in ns_records[:2]:
            stdout, stderr, rc = await query_nslookup(target, "AXFR", server=nameserver, timeout=profile["dns_timeout"])
            if rc == 0 and stdout and "Transfer failed" not in stdout and "connection timed out" not in stdout.lower():
                entry = {
                    "kind": "AXFR",
                    "name": target,
                    "value": nameserver,
                    "source": "nslookup",
                    "evidence": stdout[:500],
                }
                results.append(entry)
                yield {"module": "dns", "type": "result", "data": entry, "msg": f"AXFR appears enabled on {nameserver}", "level": "error"}
            else:
                yield {"module": "dns", "type": "log", "msg": f"AXFR denied on {nameserver}", "level": "dim"}
            break
    completed_steps += 1
    yield await emit_progress()

    if APP_SETTINGS["warn_on_wildcard_dns"]:
        wildcard_records = await detect_wildcard_dns(target)
        if wildcard_records:
            entry = {
                "kind": "WILDCARD",
                "name": target,
                "value": ", ".join(wildcard_records),
                "source": "socket.getaddrinfo",
                "evidence": f"Random subdomain resolved to {', '.join(wildcard_records)}",
            }
            results.append(entry)
            yield {"module": "dns", "type": "result", "data": entry, "msg": f"Wildcard DNS detected -> {entry['value']}", "level": "warn"}
    completed_steps += 1
    yield await emit_progress()

    yield {
        "module": "dns",
        "type": "done",
        "msg": f"dns complete - {len(results)} records and signals collected",
        "level": "success",
        "count": len(results),
    }


async def fetch_certificate_details(host: str, timeout: int = 8) -> Optional[dict]:
    def _fetch() -> Optional[dict]:
        context = ssl.create_default_context()
        with socket.create_connection((host, 443), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as tls_sock:
                cert = tls_sock.getpeercert()
                if not cert:
                    return None
                subject = {key: value for item in cert.get("subject", ()) for key, value in item}
                issuer = {key: value for item in cert.get("issuer", ()) for key, value in item}
                san = [value for kind, value in cert.get("subjectAltName", ()) if kind == "DNS"]
                return {
                    "subject_common_name": subject.get("commonName"),
                    "issuer_common_name": issuer.get("commonName"),
                    "not_before": cert.get("notBefore"),
                    "not_after": cert.get("notAfter"),
                    "san_count": len(san),
                    "san_preview": san[:5],
                }

    try:
        return await asyncio.to_thread(_fetch)
    except Exception:
        return None


def detect_frameworks_from_headers(headers: dict[str, str], body: str) -> list[str]:
    lowered_headers = {key.lower(): value for key, value in headers.items()}
    detections = set()

    server = lowered_headers.get("server", "").lower()
    powered_by = lowered_headers.get("x-powered-by", "").lower()
    generator = lowered_headers.get("x-generator", "").lower()
    cookies = lowered_headers.get("set-cookie", "").lower()
    body_lower = body.lower()

    if "cloudflare" in server or "cf-ray" in lowered_headers:
        detections.add("Cloudflare")
    if "akamai" in server or "akamai" in lowered_headers.get("x-akamai-transformed", "").lower():
        detections.add("Akamai")
    if "sucuri" in server or "x-sucuri-id" in lowered_headers:
        detections.add("Sucuri")
    if "fastly" in lowered_headers.get("x-served-by", "").lower() or "fastly" in server:
        detections.add("Fastly")
    if "wordpress" in generator or "wp-content" in body_lower:
        detections.add("WordPress")
    if "laravel" in powered_by or "laravel_session" in cookies:
        detections.add("Laravel")
    if "express" in powered_by:
        detections.add("Express")
    if "__next_data__" in body_lower or "/_next/" in body_lower:
        detections.add("Next.js")
    if 'ng-version=' in body_lower:
        detections.add("Angular")
    if '/_nuxt/' in body_lower or 'id="__nuxt"' in body_lower:
        detections.add("Nuxt")
    if "react" in body_lower and "__next_data__" not in body_lower:
        detections.add("React")
    if "drupal" in generator:
        detections.add("Drupal")

    return sorted(detections)


def detect_waf_or_cdn(headers: dict[str, str]) -> list[str]:
    lowered_headers = {key.lower(): value for key, value in headers.items()}
    signals = []
    if "cf-ray" in lowered_headers or lowered_headers.get("server", "").lower() == "cloudflare":
        signals.append("Cloudflare")
    if "x-sucuri-id" in lowered_headers:
        signals.append("Sucuri")
    if "x-akamai-transformed" in lowered_headers or "akamai" in lowered_headers.get("server", "").lower():
        signals.append("Akamai")
    if "x-served-by" in lowered_headers and "fastly" in lowered_headers["x-served-by"].lower():
        signals.append("Fastly")
    if "x-amz-cf-id" in lowered_headers or "cloudfront" in lowered_headers.get("server", "").lower():
        signals.append("CloudFront")
    return sorted(set(signals))


async def run_fingerprint_scan(target: str, subdomains: list, profile: dict) -> AsyncGenerator[dict, None]:
    yield {"module": "fingerprint", "type": "log", "msg": f"Starting fingerprint for {target}"}
    candidate_urls = [f"https://{target}", f"http://{target}"]
    for subdomain in subdomains[:2]:
        if subdomain.get("status") == "live":
            candidate_urls.append(f"https://{subdomain['name']}")

    results: list[dict] = []
    total_steps = max(1, len(candidate_urls) + 1)
    completed_steps = 0

    for url in candidate_urls:
        try:
            body, headers, status_code, final_url = await fetch_url_bytes(
                url,
                timeout=profile["fingerprint_timeout"],
                max_bytes=8192,
                profile=profile,
            )
            text = body.decode(errors="ignore")
            server_header = headers.get("Server") or headers.get("server")
            if server_header:
                entry = {
                    "kind": "HEADER",
                    "name": final_url,
                    "value": server_header,
                    "status_code": status_code,
                    "source": "http headers",
                    "evidence": f"Server: {server_header}",
                }
                results.append(entry)
                yield {"module": "fingerprint", "type": "result", "data": entry, "msg": f"Server header {final_url} -> {server_header}"}

            for framework in detect_frameworks_from_headers(headers, text):
                entry = {
                    "kind": "FRAMEWORK",
                    "name": final_url,
                    "value": framework,
                    "status_code": status_code,
                    "source": "headers/html",
                    "evidence": f"Fingerprint matched for {framework}",
                }
                results.append(entry)
                yield {"module": "fingerprint", "type": "result", "data": entry, "msg": f"Framework detected -> {framework}", "level": "success"}

            for signal in detect_waf_or_cdn(headers):
                entry = {
                    "kind": "WAF_CDN",
                    "name": final_url,
                    "value": signal,
                    "status_code": status_code,
                    "source": "headers",
                    "evidence": f"WAF/CDN signal {signal}",
                }
                results.append(entry)
                yield {"module": "fingerprint", "type": "result", "data": entry, "msg": f"WAF/CDN signal -> {signal}", "level": "warn"}
        except Exception as exc:
            yield {"module": "fingerprint", "type": "log", "msg": f"Fingerprint request failed for {url}: {exc}", "level": "warn"}

        completed_steps += 1
        yield {"module": "fingerprint", "type": "progress", "progress": int((completed_steps / total_steps) * 100)}

    cert_details = await fetch_certificate_details(target, timeout=profile["fingerprint_timeout"])
    if cert_details:
        entry = {
            "kind": "TLS",
            "name": target,
            "value": cert_details.get("subject_common_name") or target,
            "source": "ssl",
            "evidence": f"Issuer={cert_details.get('issuer_common_name')} SANs={cert_details.get('san_count')} Expiry={cert_details.get('not_after')}",
            **cert_details,
        }
        results.append(entry)
        yield {"module": "fingerprint", "type": "result", "data": entry, "msg": f"TLS cert {target} -> issuer {cert_details.get('issuer_common_name')}", "level": "success"}
    completed_steps += 1
    yield {"module": "fingerprint", "type": "progress", "progress": 100}

    yield {
        "module": "fingerprint",
        "type": "done",
        "msg": f"fingerprint complete - {len(results)} signals collected",
        "level": "success",
        "count": len(results),
    }


INTERESTING_URL_EXTENSIONS = {".json", ".xml", ".bak", ".zip", ".env", ".sql", ".gz", ".yml", ".yaml"}


def extract_urls_from_text(text: str, base_url: str) -> set[str]:
    found = set()
    for match in re.findall(r'https?://[^\s"\'<>]+', text):
        found.add(match.rstrip('.,);'))
    for match in re.findall(r'["\']((?:/|\.?/)[^"\']+)["\']', text):
        if any(token in match.lower() for token in ("/api/", "/graphql", ".json", ".xml", ".zip", ".bak", "swagger")):
            found.add(urllib_parse.urljoin(base_url, match))
    return found


def classify_url_intel_item(url: str) -> list[dict]:
    parsed = urllib_parse.urlsplit(url)
    path = parsed.path or "/"
    query_items = urllib_parse.parse_qsl(parsed.query, keep_blank_values=True)
    findings = []

    if query_items:
        for key, _ in query_items:
            findings.append({
                "kind": "PARAM",
                "name": key,
                "value": url,
                "source": "url parse",
                "evidence": f"Parameter {key} in {url}",
            })

    extension = Path(path).suffix.lower()
    if extension in INTERESTING_URL_EXTENSIONS:
        findings.append({
            "kind": "INTERESTING_FILE",
            "name": path,
            "value": extension,
            "source": "url parse",
            "evidence": url,
        })

    if any(token in path.lower() for token in ("/api/", "/graphql", "/swagger", "/openapi", "/rest/", "/v1/", "/v2/")):
        findings.append({
            "kind": "API_ROUTE",
            "name": path,
            "value": url,
            "source": "url parse",
            "evidence": url,
        })

    return findings


async def run_url_intelligence(target: str, subdomains: list, profile: dict) -> AsyncGenerator[dict, None]:
    yield {"module": "url_intel", "type": "log", "msg": f"Starting url_intel for {target}"}

    urls: set[str] = set()
    archived_urls: set[str] = set()
    base_targets = [f"https://{target}", f"http://{target}"]
    for subdomain in subdomains[:5]:
        if subdomain.get("status") == "live":
            base_targets.append(f"https://{subdomain['name']}")

    if tool_available("gau"):
        yield {"module": "url_intel", "type": "log", "msg": "Collecting archived URLs via gau..."}
        stdout, stderr, rc = await run_cmd(["gau", "--subs", target], timeout=profile["urlintel_timeout"])
        if rc == 0:
            for line in stdout.splitlines():
                url = line.strip()
                if url.startswith(("http://", "https://")):
                    urls.add(url)
                    archived_urls.add(url)
            yield {"module": "url_intel", "type": "log", "msg": f"gau collected {len(urls)} archived URLs"}
        else:
            yield {"module": "url_intel", "type": "log", "msg": f"gau error: {(stderr or 'no output')[:120]}", "level": "warn"}

    for base_url in base_targets[:profile["js_page_limit"] + 1]:
        for suffix in ("", "/robots.txt", "/sitemap.xml"):
            probe_url = base_url.rstrip("/") + suffix
            try:
                text = await fetch_url_text(
                    probe_url,
                    timeout=profile["fingerprint_timeout"],
                    max_bytes=200_000,
                    profile=profile,
                )
            except Exception:
                continue
            urls.update(extract_urls_from_text(text, base_url))

    materialized_urls = list(sorted(urls))[:profile["urlintel_max_urls"]]
    total = max(1, len(materialized_urls))
    findings: list[dict] = []
    seen_keys = set()

    for index, url in enumerate(materialized_urls, start=1):
        base_entry = {
            "kind": "ARCHIVED_URL",
            "name": urllib_parse.urlsplit(url).path or "/",
            "value": url,
            "source": "gau" if url in archived_urls else "crawl",
            "evidence": url,
        }
        entry_key = ("ARCHIVED_URL", base_entry["value"])
        if entry_key not in seen_keys:
            seen_keys.add(entry_key)
            findings.append(base_entry)
            yield {"module": "url_intel", "type": "result", "data": base_entry, "msg": f"URL {base_entry['value']}", "level": "dim"}

        for derived in classify_url_intel_item(url):
            derived_key = (derived["kind"], derived["name"], derived["value"])
            if derived_key in seen_keys:
                continue
            seen_keys.add(derived_key)
            findings.append(derived)
            level = "warn" if derived["kind"] in {"PARAM", "API_ROUTE", "INTERESTING_FILE"} else ""
            yield {"module": "url_intel", "type": "result", "data": derived, "msg": f"{derived['kind']} {derived['name']}", "level": level}

        yield {"module": "url_intel", "type": "progress", "progress": int((index / total) * 100)}

    yield {
        "module": "url_intel",
        "type": "done",
        "msg": f"url_intel complete - {len(findings)} signals collected",
        "level": "success",
        "count": len(findings),
    }


# Module: Subdomain Enumeration

async def run_subdomain_enum(target: str, profile: dict) -> AsyncGenerator[dict, None]:
    """
    Uses subfinder -> httpx pipeline.
    Falls back to pure DNS resolution if tools not available.
    """
    yield {"module": "subdomain", "type": "log", "msg": f"Starting subdomain enumeration for {target}"}

    subdomains_raw = []
    discovery_source = "subfinder"

    # subfinder
    if tool_available("subfinder"):
        yield {"module": "subdomain", "type": "log", "msg": "Running subfinder..."}
        stdout, stderr, rc = await run_cmd(
            ["subfinder", "-d", target, "-silent", "-all"],
            timeout=profile["subdomain_timeout"],
        )
        if rc == 0 and stdout.strip():
            raw_candidates = [sub.strip() for sub in stdout.strip().splitlines() if sub.strip()]
            subdomains_raw, ignored_candidates = filter_subdomain_candidates(raw_candidates, target)
            if ignored_candidates:
                yield {
                    "module": "subdomain",
                    "type": "log",
                    "msg": f"Ignored {ignored_candidates} invalid subfinder lines",
                    "level": "warn",
                }
            yield {"module": "subdomain", "type": "log", "msg": f"subfinder found {len(subdomains_raw)} candidates"}
        else:
            yield {
                "module": "subdomain",
                "type": "log",
                "msg": f"subfinder error: {stderr[:100]}",
                "level": "warn",
            }
    if not subdomains_raw:
        discovery_source = "dns fallback"
        if tool_available("subfinder"):
            yield {"module": "subdomain", "type": "log", "msg": "subfinder produced no candidates - using DNS fallback", "level": "warn"}
        else:
            yield {"module": "subdomain", "type": "log", "msg": "subfinder not found - using DNS fallback", "level": "warn"}
        common = ["www", "api", "dev", "staging", "mail", "admin", "portal", "vpn", "shop", "beta", "cdn", "internal"]
        for prefix in common:
            sub = f"{prefix}.{target}"
            try:
                socket.gethostbyname(sub)
                subdomains_raw.append(sub)
            except socket.gaierror:
                pass
        yield {"module": "subdomain", "type": "log", "msg": f"DNS fallback found {len(subdomains_raw)} candidates"}

    if not subdomains_raw:
        yield {"module": "subdomain", "type": "log", "msg": "No subdomains found", "level": "warn"}
        return

    # httpx probe for live check
    results = []
    total = max(1, len(subdomains_raw))
    processed = 0
    httpx_command = resolve_httpx_command()
    if httpx_command:
        yield {"module": "subdomain", "type": "log", "msg": "Probing live status with httpx..."}
        stdout, stderr, rc = await run_cmd(
            [httpx_command, "-silent", "-status-code", "-ip", "-no-color"],
            timeout=profile["httpx_timeout"],
            input_data="\n".join(subdomains_raw).encode(),
        )
        if rc != 0:
            yield {
                "module": "subdomain",
                "type": "log",
                "msg": f"httpx error: {(stderr or 'probe failed')[:160]}",
                "level": "warn",
            }
        ignored_probe_lines = 0
        for line in stdout.splitlines():
            parts = line.strip().split()
            if not parts:
                continue
            url = normalize_subdomain_candidate(parts[0], target)
            if not url:
                ignored_probe_lines += 1
                continue
            code = parts[1].strip("[]") if len(parts) > 1 else "?"
            ip = parts[2].strip("[]") if len(parts) > 2 else "?"
            status = "live" if code in ("200", "301", "302", "403") else "dead"
            entry = {
                "name": url,
                "ip": ip,
                "status": status,
                "code": code,
                "source": f"{discovery_source} -> httpx",
                "evidence": line.strip(),
            }
            results.append(entry)
            processed += 1
            yield {
                "module": "subdomain",
                "type": "result",
                "data": entry,
                "msg": f"{'✓' if status == 'live' else '✗'} {url} [{ip}] {code}",
                "level": "success" if status == "live" else "dim",
            }
            yield {"module": "subdomain", "type": "progress", "progress": int((processed / total) * 100)}
        if ignored_probe_lines:
            yield {
                "module": "subdomain",
                "type": "log",
                "msg": f"Ignored {ignored_probe_lines} invalid httpx output lines",
                "level": "warn",
            }
    if not httpx_command and tool_available("httpx"):
        yield {
            "module": "subdomain",
            "type": "log",
            "msg": "Found an httpx command, but it is not ProjectDiscovery httpx. Skipping live probe.",
            "level": "warn",
        }
    if not results:
        for sub in subdomains_raw:
            try:
                ip = socket.gethostbyname(sub)
                entry = {
                    "name": sub,
                    "ip": ip,
                    "status": "live",
                    "code": "?",
                    "source": f"{discovery_source} -> dns" if discovery_source != "dns fallback" else discovery_source,
                    "evidence": f"socket.gethostbyname({sub}) -> {ip}",
                }
            except socket.gaierror:
                entry = {
                    "name": sub,
                    "ip": "-",
                    "status": "dead",
                    "code": "-",
                    "source": f"{discovery_source} -> dns" if discovery_source != "dns fallback" else discovery_source,
                    "evidence": f"socket.gethostbyname({sub}) failed",
                }
            results.append(entry)
            processed += 1
            yield {
                "module": "subdomain",
                "type": "result",
                "data": entry,
                "msg": f"{'✓' if entry['status'] == 'live' else '✗'} {sub} [{entry['ip']}]",
                "level": "success" if entry["status"] == "live" else "dim",
            }
            yield {"module": "subdomain", "type": "progress", "progress": int((processed / total) * 100)}

    live = sum(1 for result in results if result["status"] == "live")
    yield {
        "module": "subdomain",
        "type": "done",
        "msg": f"Enumeration complete - {len(results)} subdomains, {live} live",
        "level": "success",
        "count": len(results),
    }


# Module: Port Scanning

CRITICAL_PORTS = {3306, 5432, 6379, 27017, 9200, 9042, 2181, 11211}
INTERESTING_PORTS = {21, 22, 23, 25, 53, 8080, 8443, 8888, 9090, 4848}

SERVICE_MAP = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    3306: "MySQL",
    5432: "PostgreSQL",
    6379: "Redis",
    8080: "HTTP-ALT",
    8443: "HTTPS-ALT",
    9200: "Elasticsearch",
    27017: "MongoDB",
    11211: "Memcached",
    9042: "Cassandra",
    2181: "ZooKeeper",
    4848: "GlassFish",
    8888: "Jupyter",
    9090: "Prometheus",
}


async def run_port_scan(target: str, ports: str, profile: dict) -> AsyncGenerator[dict, None]:
    yield {"module": "port", "type": "log", "msg": f"Port scanning {target} on ports: {ports}"}

    if tool_available("nmap"):
        yield {"module": "port", "type": "log", "msg": "Running nmap SYN scan (may require sudo/admin)..." }
        stdout, stderr, rc = await run_cmd(
            ["nmap", "-p", ports, "--open", "-sV", "-T4", "--host-timeout", "30s", "-oG", "-", target],
            timeout=profile["port_timeout"],
        )
        if rc != 0 and "requires root" in stderr.lower():
            yield {
                "module": "port",
                "type": "log",
                "msg": "SYN scan needs elevated privileges - falling back to TCP connect scan",
                "level": "warn",
            }
            stdout, stderr, rc = await run_cmd(
                ["nmap", "-p", ports, "--open", "-sT", "-T4", "--host-timeout", "30s", "-oG", "-", target],
                timeout=profile["port_timeout"],
            )

        open_ports = []
        for line in stdout.splitlines():
            if "Ports:" not in line:
                continue
            port_section = re.findall(r"(\d+)/open/tcp//([^/]*)", line)
            for port_str, service_raw in port_section:
                port = int(port_str)
                service = SERVICE_MAP.get(port, service_raw.strip() or "unknown")
                critical = port in CRITICAL_PORTS
                interesting = port in INTERESTING_PORTS
                entry = {
                    "port": port,
                    "service": service,
                    "critical": critical,
                    "interesting": interesting,
                    "source": "nmap",
                    "evidence": line.strip(),
                }
                open_ports.append(entry)
                level = "error" if critical else "warn" if interesting else ""
                tag = " 🔴 CRITICAL" if critical else " 🟡 INTERESTING" if interesting else ""
                yield {"module": "port", "type": "result", "data": entry, "msg": f"Open: {port}/{service}{tag}", "level": level}

        yield {
            "module": "port",
            "type": "done",
            "msg": f"Scan complete - {len(open_ports)} open ports found",
            "level": "success",
            "count": len(open_ports),
        }

    else:
        yield {"module": "port", "type": "log", "msg": "nmap not found - using Python TCP connect fallback", "level": "warn"}
        port_list = [int(port.strip()) for port in ports.split(",") if port.strip().isdigit()]
        open_ports = []
        for port in port_list:
            try:
                with socket.create_connection((target, port), timeout=1.5):
                    service = SERVICE_MAP.get(port, "unknown")
                    critical = port in CRITICAL_PORTS
                    interesting = port in INTERESTING_PORTS
                    entry = {
                        "port": port,
                        "service": service,
                        "critical": critical,
                        "interesting": interesting,
                        "source": "python socket",
                        "evidence": f"tcp connect to {target}:{port} succeeded",
                    }
                    open_ports.append(entry)
                    tag = " 🔴 CRITICAL" if critical else " 🟡 INTERESTING" if interesting else ""
                    yield {
                        "module": "port",
                        "type": "result",
                        "data": entry,
                        "msg": f"Open: {port}/{service}{tag}",
                        "level": "error" if critical else "warn" if interesting else "",
                    }
            except (socket.timeout, ConnectionRefusedError, OSError):
                pass

        yield {
            "module": "port",
            "type": "done",
            "msg": f"Scan complete - {len(open_ports)} open ports found",
            "level": "success",
            "count": len(open_ports),
        }


# Module: JS Analysis

JS_PATTERNS = [
    ("API_KEY", r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9\-_]{20,})["\']', "high"),
    ("GOOGLE_API_KEY", r"AIza[0-9A-Za-z\-_]{35}", "high"),
    ("AWS_KEY", r"AKIA[0-9A-Z]{16}", "high"),
    ("AWS_SECRET", r'(?:aws[_-]?secret|secret[_-]?access[_-]?key)\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']', "high"),
    ("JWT_SECRET", r'(?:jwt[_-]?secret|secret)\s*[=:]\s*["\']([A-Za-z0-9\-_]{16,})["\']', "high"),
    ("OAUTH_SECRET", r'client[_-]?secret\s*[=:]\s*["\']([A-Za-z0-9\-_]{16,})["\']', "high"),
    ("STRIPE_SECRET", r"sk_live_[0-9A-Za-z]{16,}", "high"),
    ("STRIPE_PUBLISHABLE", r"pk_live_[0-9A-Za-z]{16,}", "medium"),
    ("GITHUB_TOKEN", r"(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{40,})", "high"),
    ("SLACK_TOKEN", r"xox[baprs]-[A-Za-z0-9-]{10,}", "high"),
    ("SENDGRID_KEY", r"SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,}", "high"),
    ("PRIVATE_KEY_HEADER", r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----", "critical"),
    ("S3_BUCKET", r"s3\.amazonaws\.com/([a-z0-9\-]{3,63})", "medium"),
    ("INTERNAL_ENDPOINT", r'["\']/(api|internal|admin|v\d+)/[a-zA-Z0-9/_\-]+["\']', "medium"),
    ("GRAPHQL", r'(?:graphql|gql)\s*[=:]\s*["\']([^"\']+)["\']', "info"),
    ("SOURCEMAP", r"sourceMappingURL\s*=\s*(.+\.map)", "info"),
    ("HARDCODED_PASSWORD", r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']', "high"),
    ("PRIVATE_IP", r"(?:10\.|192\.168\.|172\.(?:1[6-9]|2[0-9]|3[01])\.)\d{1,3}\.\d{1,3}", "medium"),
    ("FIREBASE", r"firebaseio\.com/([a-zA-Z0-9\-]+)", "medium"),
]


def validate_secret_match(pattern_name: str, value: str) -> str:
    if pattern_name in {"GOOGLE_API_KEY", "AWS_KEY", "STRIPE_SECRET", "STRIPE_PUBLISHABLE", "SENDGRID_KEY"}:
        return "format-validated"
    if pattern_name in {"GITHUB_TOKEN", "SLACK_TOKEN"}:
        return "format-validated"
    if pattern_name in {"API_KEY", "JWT_SECRET", "OAUTH_SECRET", "HARDCODED_PASSWORD"}:
        return "contextual-match"
    return "pattern-match"


def extract_js_endpoints(content: str, base_url: str, limit: int) -> list[str]:
    discovered = set()
    for match in re.findall(r'https?://[^\s"\'<>]+', content):
        discovered.add(match.rstrip('.,);'))
    for match in re.findall(r'["\']((?:/|\.?/)[^"\']+)["\']', content):
        lowered = match.lower()
        if any(token in lowered for token in ("/api/", "/graphql", "/admin", "/internal", "/v1/", "/v2/", ".json")):
            discovered.add(urllib_parse.urljoin(base_url, match))
    return list(sorted(discovered))[:limit]


async def run_js_analysis(target: str, subdomains: list, profile: dict) -> AsyncGenerator[dict, None]:
    """Crawl JS files from target and subdomains, then scan for secrets."""
    yield {"module": "js", "type": "log", "msg": f"Starting JS analysis on {target} and {len(subdomains)} subdomains"}

    urls_to_check = [f"https://{target}", f"http://{target}"]
    for sub in subdomains[:10]:
        if sub.get("status") == "live":
            urls_to_check.append(f"https://{sub['name']}")

    js_urls = set()
    discovery_method = "page crawl"

    async def crawl_pages_for_js(base_urls: list[str]) -> set[str]:
        found_urls = set()
        for base_url in base_urls:
            try:
                html = await fetch_url_text(base_url, timeout=8, max_bytes=250_000, profile=profile)
            except Exception:
                continue

            found = re.findall(r'<script[^>]+src=["\']([^"\']+\.js[^"\']*)["\']', html)
            for item in found:
                found_urls.add(urllib_parse.urljoin(base_url, item))
        return found_urls

    # Use gau to find JS URLs first, then fall back to a lightweight crawl.
    if tool_available("gau"):
        discovery_method = "gau"
        yield {"module": "js", "type": "log", "msg": "Fetching known URLs via gau..."}
        try:
            stdout, stderr, rc = await run_cmd(["gau", "--subs", target], timeout=profile["gau_timeout"])
            if rc == 0:
                for line in stdout.splitlines():
                    url = line.strip()
                    if ".js" in url and "min.js" not in url and url.startswith(("http://", "https://")):
                        js_urls.add(url)
                yield {"module": "js", "type": "log", "msg": f"gau found {len(js_urls)} JS file URLs"}
            else:
                yield {
                    "module": "js",
                    "type": "log",
                    "msg": f"gau error: {(stderr or 'unable to enumerate URLs')[:160]}",
                    "level": "warn",
                }
        except Exception as exc:
            yield {
                "module": "js",
                "type": "log",
                "msg": f"gau failed on this run: {exc}",
                "level": "warn",
            }
    else:
        yield {"module": "js", "type": "log", "msg": "gau not found - using page crawl fallback", "level": "warn"}

    if not js_urls:
        discovery_method = "page crawl"
        yield {"module": "js", "type": "log", "msg": "Crawling pages for script sources..."}
        js_urls = await crawl_pages_for_js(urls_to_check[:profile["js_page_limit"]])
        yield {"module": "js", "type": "log", "msg": f"Page crawl found {len(js_urls)} JS file URLs"}

    if not js_urls:
        yield {"module": "js", "type": "log", "msg": "No JS files found to analyze", "level": "warn"}
        yield {
            "module": "js",
            "type": "done",
            "msg": "Analysis complete - 0 files scanned, 0 findings",
            "level": "success",
            "count": 0,
            "analyzed": 0,
        }
        return

    findings = []
    analyzed = 0
    js_candidates = list(sorted(js_urls))[:profile["js_max_files"]]

    async def analyze_js_file(js_url: str, allow_source_map: bool) -> Optional[dict]:
        try:
            content = await fetch_url_text(js_url, timeout=profile["js_fetch_timeout"], max_bytes=500_000, profile=profile)
        except Exception:
            return None

        file_findings = []
        for endpoint in extract_js_endpoints(content, js_url, profile["js_endpoint_limit"]):
            file_findings.append(
                {
                    "type": "ENDPOINT_EXTRACTED" if "graphql" not in endpoint.lower() else "GRAPHQL_ENDPOINT",
                    "url": js_url,
                    "detail": endpoint,
                    "severity": "info" if "graphql" not in endpoint.lower() else "medium",
                    "source": f"{discovery_method} + endpoint extraction",
                    "evidence": f"Endpoint extracted from {js_url}",
                    "redacted": False,
                    "validation": "reachable-check-pending",
                }
            )

        if allow_source_map:
            source_map_matches = re.findall(r"sourceMappingURL\s*=\s*([^\s]+\.map)", content, re.IGNORECASE)
            for source_map_ref in source_map_matches[:1]:
                source_map_url = urllib_parse.urljoin(js_url, source_map_ref.strip())
                file_findings.append(
                    {
                        "type": "SOURCE_MAP_URL",
                        "url": js_url,
                        "detail": source_map_url,
                        "severity": "info",
                        "source": f"{discovery_method} + source map",
                        "evidence": f"Source map reference in {js_url}",
                        "redacted": False,
                        "validation": "reference-found",
                    }
                )
                try:
                    source_map_text = await fetch_url_text(
                        source_map_url,
                        timeout=profile["js_fetch_timeout"],
                        max_bytes=700_000,
                        profile=profile,
                    )
                    for endpoint in extract_js_endpoints(source_map_text, js_url, max(8, profile["js_endpoint_limit"] // 2)):
                        file_findings.append(
                            {
                                "type": "SOURCE_MAP_ENDPOINT",
                                "url": source_map_url,
                                "detail": endpoint,
                                "severity": "medium" if "admin" in endpoint.lower() or "internal" in endpoint.lower() else "info",
                                "source": "source map + endpoint extraction",
                                "evidence": f"Endpoint extracted from source map {source_map_url}",
                                "redacted": False,
                                "validation": "source-map-confirmed",
                            }
                        )
                except Exception:
                    pass

        for pattern_name, pattern, severity in JS_PATTERNS:
            matches = re.findall(pattern, content, re.IGNORECASE)
            if not matches:
                continue
            match_value = matches[0]
            if isinstance(match_value, tuple):
                match_value = " | ".join(str(part) for part in match_value if part)
            match_text = str(match_value)
            detail_value = redact_sensitive_value(match_text) if finding_is_sensitive(pattern_name) else match_text[:60]
            file_findings.append(
                {
                    "type": pattern_name,
                    "url": js_url,
                    "detail": f"Match: {detail_value}{' (redacted)' if finding_is_sensitive(pattern_name) else ''}",
                    "severity": severity,
                    "source": f"{discovery_method} + regex",
                    "evidence": f"{pattern_name} matched in {js_url}",
                    "redacted": finding_is_sensitive(pattern_name),
                    "validation": validate_secret_match(pattern_name, match_text),
                }
            )

        return {"url": js_url, "findings": file_findings}

    analysis_tasks = [
        analyze_js_file(js_url, index < profile["js_source_map_limit"])
        for index, js_url in enumerate(js_candidates)
    ]

    for task in asyncio.as_completed(analysis_tasks):
        result = await task
        if not result:
            continue

        analyzed += 1
        for entry in result["findings"]:
            findings.append(entry)
            severity = entry["severity"]
            yield {
                "module": "js",
                "type": "result",
                "data": entry,
                "msg": f"[{severity.upper()}] {entry['type']} in {entry['url'].split('/')[-1]}",
                "level": "error" if severity in ("high", "critical") else "warn" if severity == "medium" else "",
            }
        yield {"module": "js", "type": "progress", "progress": int((analyzed / max(1, len(js_candidates))) * 100)}

    yield {
        "module": "js",
        "type": "done",
        "msg": f"Analysis complete - {analyzed} files scanned, {len(findings)} findings",
        "level": "success",
        "count": len(findings),
        "analyzed": analyzed,
    }


# Module: Directory Fuzzing

def resolve_wordlist_path(wordlist: Optional[str]) -> Optional[str]:
    candidates = []
    if wordlist:
        candidates.append(wordlist)

    env_wordlist = os.environ.get("RECON_WORDLIST")
    if env_wordlist:
        candidates.append(env_wordlist)

    candidates.extend(
        [
            "/usr/share/wordlists/dirb/common.txt",
            "/usr/share/dirb/wordlists/common.txt",
            "/opt/homebrew/share/dirb/wordlists/common.txt",
            str(Path.home() / "SecLists" / "Discovery" / "Web-Content" / "common.txt"),
            str(Path.home() / "tools" / "SecLists" / "Discovery" / "Web-Content" / "common.txt"),
            str(Path.cwd() / "wordlists" / "common.txt"),
            str(Path.cwd() / "common.txt"),
        ]
    )

    for candidate in candidates:
        if candidate and os.path.exists(candidate):
            return candidate
    return None


def expand_dir_words(words: list[str], extensions: list[str]) -> list[str]:
    expanded = []
    seen = set()
    seed_words = [word.strip().lstrip("/") for word in words if word.strip()]
    extras = [".env", ".git/config", "backup.zip", "config.json", "swagger.json", "openapi.json"]

    for word in seed_words + extras:
        variants = [word]
        if "/" not in word and not any(word.endswith(ext) for ext in extensions):
            variants.extend([f"{word}{ext}" for ext in extensions])
        for variant in variants:
            if variant in seen:
                continue
            seen.add(variant)
            expanded.append(variant)
    return expanded


async def fetch_response_signature(url: str, profile: dict) -> tuple[int, int]:
    try:
        body, _, status_code, _ = await fetch_url_bytes(
            url,
            timeout=profile["fingerprint_timeout"],
            max_bytes=2048,
            profile=profile,
        )
        return status_code, len(body)
    except Exception:
        return 0, 0


async def run_dir_fuzzing(target: str, wordlist: Optional[str], profile: dict) -> AsyncGenerator[dict, None]:
    yield {"module": "dir", "type": "log", "msg": f"Directory fuzzing https://{target}"}

    resolved_wordlist = resolve_wordlist_path(wordlist)
    if not resolved_wordlist:
        yield {
            "module": "dir",
            "type": "log",
            "msg": "No wordlist found. Install dirb or provide a wordlist path.",
            "level": "warn",
        }
        yield {"module": "dir", "type": "done", "msg": "Dir fuzzing skipped - no wordlist", "count": 0}
        return

    if resolved_wordlist != wordlist:
        yield {"module": "dir", "type": "log", "msg": f"Using wordlist: {resolved_wordlist}"}

    baseline_code, baseline_size = await fetch_response_signature(
        f"https://{target}/recon-miss-{uuid.uuid4().hex[:8]}",
        profile,
    )
    if baseline_code:
        yield {"module": "dir", "type": "log", "msg": f"Baseline response signature: {baseline_code}/{baseline_size}B", "level": "dim"}

    if tool_available("ffuf"):
        yield {"module": "dir", "type": "log", "msg": "Running ffuf..."}
        ffuf_output = Path(tempfile.gettempdir()) / f"recon_ffuf_{uuid.uuid4().hex}.json"
        results = []
        try:
            await run_cmd(
                [
                    "ffuf",
                    "-w",
                    resolved_wordlist,
                    "-u",
                    f"https://{target}/FUZZ",
                    "-mc",
                    "200,204,301,302,403,500",
                    "-fs",
                    str(baseline_size),
                    "-t",
                    "40",
                    "-timeout",
                    "5",
                    "-of",
                    "json",
                    "-o",
                    str(ffuf_output),
                    "-s",
                ],
                timeout=profile["dir_tool_timeout"],
            )

            if ffuf_output.exists():
                try:
                    with ffuf_output.open(encoding="utf-8") as handle:
                        data = json.load(handle)
                    for result in data.get("results", []):
                        code = result.get("status", 0)
                        path = "/" + result.get("input", {}).get("FUZZ", "")
                        size = f"{result.get('length', 0)} B"
                        entry = {
                            "path": path,
                            "code": code,
                            "size": size,
                            "source": "ffuf",
                            "evidence": f"status={code} size={size}",
                        }
                        results.append(entry)
                        level = "success" if code == 200 else "warn" if code == 403 else ""
                        yield {
                            "module": "dir",
                            "type": "result",
                            "data": entry,
                            "msg": f"[{code}] {path}  {size}",
                            "level": level,
                        }
                except Exception as exc:
                    yield {
                        "module": "dir",
                        "type": "log",
                        "msg": f"Failed to parse ffuf output: {exc}",
                        "level": "warn",
                    }
        finally:
            if ffuf_output.exists():
                ffuf_output.unlink(missing_ok=True)

        yield {
            "module": "dir",
            "type": "done",
            "msg": f"Fuzzing complete - {len(results)} paths found",
            "level": "success",
            "count": len(results),
        }

    else:
        yield {"module": "dir", "type": "log", "msg": "ffuf not found - using Python HTTP probe (slower)", "level": "warn"}

        with open(resolved_wordlist, encoding="utf-8", errors="ignore") as handle:
            words = [word.strip() for word in handle if word.strip() and not word.startswith("#")]

        words = expand_dir_words(words[:profile["dir_word_limit"]], profile["dir_extensions"])
        yield {"module": "dir", "type": "log", "msg": f"Probing {len(words)} paths..."}
        results = []

        async def probe(word: str, prefix: str = "") -> Optional[dict]:
            normalized_word = word.lstrip("/")
            path = f"{prefix}/{normalized_word}" if prefix else "/" + normalized_word
            url = f"https://{target}{path}"
            def _probe() -> Optional[dict]:
                try:
                    req = urllib_request.Request(url, headers={"User-Agent": "Mozilla/5.0"}, method="GET")
                    with urllib_request.urlopen(req, timeout=4) as response:
                        return {
                            "path": path,
                            "code": response.status,
                            "size": f"{len(response.read(1000))} B",
                            "source": "python probe",
                            "evidence": f"GET {url} returned {response.status}",
                        }
                except urllib_error.HTTPError as exc:
                    if exc.code in (301, 302, 403, 500):
                        return {
                            "path": path,
                            "code": exc.code,
                            "size": "-",
                            "source": "python probe",
                            "evidence": f"GET {url} returned {exc.code}",
                        }
                except Exception:
                    pass
                return None

            return await asyncio.to_thread(_probe)

        batch_size = profile["dir_batch_size"]
        queue_items = [("", word) for word in words]
        seen_paths = set()
        processed = 0
        total = max(1, len(queue_items))
        depth_map = {"": 0}

        while queue_items:
            current_prefix, _ = queue_items[0]
            batch_pairs = queue_items[:batch_size]
            queue_items = queue_items[batch_size:]
            batch_results = await asyncio.gather(*(probe(word, prefix) for prefix, word in batch_pairs))
            for entry in batch_results:
                if not entry:
                    processed += 1
                    yield {"module": "dir", "type": "progress", "progress": int((processed / total) * 100)}
                    continue
                if entry["path"] in seen_paths:
                    processed += 1
                    yield {"module": "dir", "type": "progress", "progress": int((processed / total) * 100)}
                    continue
                body_size = 0
                try:
                    body_size = int(str(entry["size"]).split()[0])
                except (ValueError, IndexError):
                    body_size = 0
                if baseline_code == entry["code"] == 200 and abs(body_size - baseline_size) <= profile["dir_similarity_tolerance"]:
                    processed += 1
                    yield {"module": "dir", "type": "progress", "progress": int((processed / total) * 100)}
                    continue
                seen_paths.add(entry["path"])
                results.append(entry)
                code = entry["code"]
                level = "success" if code == 200 else "warn" if code == 403 else ""
                yield {
                    "module": "dir",
                    "type": "result",
                    "data": entry,
                    "msg": f"[{code}] {entry['path']}  {entry['size']}",
                    "level": level,
                }
                depth = entry["path"].count("/") - 1
                if depth < profile["dir_recursion_depth"] and code in (200, 301, 302, 403):
                    sub_prefix = entry["path"].rstrip("/")
                    extra_words = ["admin", "api", "config", "debug", "v1", "v2"]
                    queue_items.extend((sub_prefix, word) for word in extra_words)
                    total += len(extra_words)
                processed += 1
                yield {"module": "dir", "type": "progress", "progress": int((processed / total) * 100)}

        yield {
            "module": "dir",
            "type": "done",
            "msg": f"Fuzzing complete - {len(results)} paths found",
            "level": "success",
            "count": len(results),
        }


# Streaming scan endpoint (SSE)

MODULE_RESULT_KEYS = {
    "subdomain": "subdomains",
    "dns": "dns_records",
    "port": "ports",
    "fingerprint": "fingerprints",
    "js": "js_findings",
    "url_intel": "url_intel",
    "dir": "directories",
}


async def ensure_scan_workers() -> None:
    global scan_job_queue, scan_workers_started, scan_worker_task, scan_worker_loop

    current_loop = asyncio.get_running_loop()
    worker_is_alive = (
        scan_workers_started
        and scan_job_queue is not None
        and scan_worker_task is not None
        and not scan_worker_task.done()
        and scan_worker_loop is current_loop
    )
    if worker_is_alive:
        return

    scan_job_queue = asyncio.Queue()
    scan_worker_loop = current_loop
    scan_worker_task = current_loop.create_task(scan_worker(scan_job_queue))
    scan_workers_started = True


def summarize_results(results: dict[str, list[dict]], module_metrics: dict[str, Any]) -> dict:
    return {
        "subdomains": len(results["subdomains"]),
        "dns_records": len(results["dns_records"]),
        "ports": len(results["ports"]),
        "fingerprints": len(results["fingerprints"]),
        "js_findings": len(results["js_findings"]),
        "url_intel": len(results["url_intel"]),
        "dirs": len(results["directories"]),
        "live_subdomains": sum(1 for item in results["subdomains"] if item.get("status") == "live"),
        "critical_ports": sum(1 for item in results["ports"] if item.get("critical")),
        "high_js_findings": sum(1 for item in results["js_findings"] if item.get("severity") in ("high", "critical")),
        "ok_dirs": sum(1 for item in results["directories"] if item.get("code") == 200),
        "js_scanned": module_metrics.get("js", {}).get("analyzed", 0),
    }


async def push_job_event(job: dict, event: dict) -> None:
    await job["queue"].put(event)
    job["last_event_at"] = datetime.utcnow().isoformat()


async def execute_scan_job(job: dict) -> None:
    target = job["target"]
    profile = job["profile"]
    modules = job["modules"]
    started_at = job["started_at"]
    scan_id = job["scan_id"]
    session_id = job["session_id"]
    job["status"] = "running"

    results = {
        "subdomains": [],
        "dns_records": [],
        "ports": [],
        "fingerprints": [],
        "js_findings": [],
        "url_intel": [],
        "directories": [],
    }
    module_metrics: dict[str, Any] = {"js": {"analyzed": 0}}
    evidence = []
    logs = []

    def record_log(module: str, event_type: str, msg: str, level: str = "") -> None:
        logs.append(
            {
                "time": datetime.utcnow().isoformat(),
                "module": module,
                "type": event_type,
                "msg": msg,
                "level": level or "info",
            }
        )

    async def emit(event: dict) -> None:
        if event.get("msg"):
            record_log(event.get("module", "system"), event.get("type", "log"), event["msg"], event.get("level", ""))
        if event.get("type") == "result" and event.get("module") in MODULE_RESULT_KEYS:
            module_name = event["module"]
            result_key = MODULE_RESULT_KEYS[module_name]
            results[result_key].append(event["data"])
            evidence.append(build_saved_evidence(module_name, event["data"]))
        if event.get("type") == "done" and event.get("module") == "js" and isinstance(event.get("analyzed"), int):
            module_metrics["js"]["analyzed"] = event["analyzed"]
        await push_job_event(job, event)

    start_event = {
        "type": "start",
        "target": target,
        "scan_id": scan_id,
        "session_id": session_id,
        "scan_mode": profile["mode"],
        "profile": profile_summary(profile),
        "time": started_at,
    }
    record_log("system", "start", f"Starting {profile['label']} scan for {target}", "success")
    await push_job_event(job, start_event)

    module_sequence = [
        ("subdomain", run_subdomain_enum(target, profile)),
        ("dns", run_dns_recon(target, profile)),
        ("port", run_port_scan(target, profile["ports"], profile)),
        ("fingerprint", run_fingerprint_scan(target, results["subdomains"], profile)),
        ("js", run_js_analysis(target, results["subdomains"], profile)),
        ("url_intel", run_url_intelligence(target, results["subdomains"], profile)),
        ("dir", run_dir_fuzzing(target, job.get("wordlist"), profile)),
    ]

    try:
        for module_name, generator in module_sequence:
            if not modules.get(module_name, False):
                continue
            try:
                async for event in generator:
                    await emit(event)
            except Exception as exc:
                await emit({
                    "module": module_name,
                    "type": "error",
                    "msg": f"{module_name} module failed: {exc}",
                    "level": "error",
                })

        completed_at = datetime.utcnow().isoformat()
        summary = summarize_results(results, module_metrics)
        job["status"] = "completed_with_errors" if any(item.get("type") == "error" for item in logs) else "completed"
        job["summary"] = summary
        report = {
            "scan_id": scan_id,
            "session_id": session_id,
            "target": target,
            "scan_mode": profile["mode"],
            "status": job["status"],
            "started_at": started_at,
            "completed_at": completed_at,
            "modules_enabled": modules,
            "profile": profile_summary(profile),
            "summary": summary,
            "results": results,
            "evidence": evidence,
            "logs": logs,
            "redaction_policy": "Sensitive key-like values are redacted in JS findings and exposed key candidates.",
        }
        save_scan_record(report)
        job["report"] = report
        await push_job_event(job, {
            "type": "complete",
            "scan_id": scan_id,
            "session_id": session_id,
            "scan_mode": profile["mode"],
            "summary": summary,
            "saved": True,
            "time": completed_at,
        })
    except Exception as exc:
        job["status"] = "failed"
        await push_job_event(job, {
            "type": "fatal",
            "scan_id": scan_id,
            "msg": f"Scan worker failed: {exc}",
            "level": "error",
        })
    finally:
        job["completed"] = True


async def scan_worker(job_queue: asyncio.Queue[str]) -> None:
    while True:
        scan_id = await job_queue.get()
        job = scans.get(scan_id)
        if job:
            await execute_scan_job(job)
        job_queue.task_done()


def build_markdown_report(record: dict) -> str:
    summary = record.get("summary", {})
    results = record.get("results", {})
    lines = [
        f"# RECON//OS Report: {record.get('target', 'target')}",
        "",
        f"- Scan ID: `{record.get('scan_id', '-')}`",
        f"- Session ID: `{record.get('session_id', '-')}`",
        f"- Scan Mode: `{record.get('scan_mode', '-')}`",
        f"- Status: `{record.get('status', '-')}`",
        f"- Started: `{record.get('started_at', '-')}`",
        f"- Completed: `{record.get('completed_at', '-')}`",
        "",
        "## Summary",
        "",
    ]
    for key, value in summary.items():
        lines.append(f"- {key}: `{value}`")

    for section_key, label in (
        ("subdomains", "Subdomains"),
        ("dns_records", "dns"),
        ("ports", "Ports"),
        ("fingerprints", "fingerprint"),
        ("js_findings", "JS Findings"),
        ("url_intel", "url_intel"),
        ("directories", "Directories"),
    ):
        lines.extend(["", f"## {label}", ""])
        items = results.get(section_key) or []
        if not items:
            lines.append("_No results._")
            continue
        for item in items[:200]:
            lines.append(f"- `{json.dumps(item, sort_keys=True)}`")
    return "\n".join(lines)


def build_html_report(record: dict) -> str:
    summary = record.get("summary", {})
    results = record.get("results", {})

    def render_list(items: list[dict]) -> str:
        if not items:
            return "<p>No results.</p>"
        entries = "".join(f"<li><code>{html.escape(json.dumps(item, sort_keys=True))}</code></li>" for item in items[:200])
        return f"<ul>{entries}</ul>"

    summary_rows = "".join(
        f"<tr><th>{html.escape(str(key))}</th><td>{html.escape(str(value))}</td></tr>"
        for key, value in summary.items()
    )
    sections = []
    for section_key, label in (
        ("subdomains", "Subdomains"),
        ("dns_records", "dns"),
        ("ports", "Ports"),
        ("fingerprints", "fingerprint"),
        ("js_findings", "JS Findings"),
        ("url_intel", "url_intel"),
        ("directories", "Directories"),
    ):
        sections.append(f"<section><h2>{html.escape(label)}</h2>{render_list(results.get(section_key) or [])}</section>")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>RECON//OS Report - {html.escape(record.get('target', 'target'))}</title>
  <style>
    body {{ font-family: Arial, sans-serif; margin: 24px; background: #0b1118; color: #e8f8ff; }}
    h1, h2 {{ color: #00ffe1; }}
    table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
    th, td {{ border: 1px solid #1a2d42; padding: 8px; text-align: left; }}
    code {{ white-space: pre-wrap; word-break: break-word; color: #c8e0f0; }}
    li {{ margin: 8px 0; }}
    section {{ margin-top: 24px; }}
  </style>
</head>
<body>
  <h1>RECON//OS Report: {html.escape(record.get('target', 'target'))}</h1>
  <p><strong>Scan ID:</strong> {html.escape(str(record.get('scan_id', '-')))}</p>
  <p><strong>Scan Mode:</strong> {html.escape(str(record.get('scan_mode', '-')))}</p>
  <p><strong>Status:</strong> {html.escape(str(record.get('status', '-')))}</p>
  <table>{summary_rows}</table>
  {''.join(sections)}
</body>
</html>"""

if __name__ == "__main__":
    import uvicorn

    uvicorn.run("reconsite.asgi:application", host="127.0.0.1", port=8000)
