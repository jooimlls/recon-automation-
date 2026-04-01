import asyncio
import json
import re
import uuid
from datetime import datetime

from django.http import HttpResponse, HttpResponseNotAllowed, JsonResponse, StreamingHttpResponse
from django.shortcuts import render
from pydantic import ValidationError

import recon_api


def _json_error(detail: str, status: int) -> JsonResponse:
    return JsonResponse({"detail": detail}, status=status)


def _report_filename(record: dict, extension: str) -> str:
    filename_target = re.sub(r"[^a-z0-9.-]+", "-", record["target"]).strip("-") or "target"
    return f"recon-report-{filename_target}-{record['scan_id']}.{extension}"


def dashboard(request):
    if request.method != "GET":
        return HttpResponseNotAllowed(["GET"])
    return render(request, "reconweb/dashboard.html")


def docs(request):
    if request.method != "GET":
        return HttpResponseNotAllowed(["GET"])

    body = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>RECON//OS Django API</title>
  <style>
    body { font-family: Arial, sans-serif; margin: 24px; background: #0b1118; color: #e8f8ff; }
    h1, h2 { color: #00ffe1; }
    code { background: rgba(255,255,255,0.06); padding: 2px 6px; border-radius: 4px; }
    li { margin: 10px 0; }
    a { color: #00ffe1; }
  </style>
</head>
<body>
  <h1>RECON//OS Django API</h1>
  <p>The dashboard is served at <a href="/">/</a>. Scan streaming uses Server-Sent Events from <code>POST /scan</code>.</p>
  <h2>Endpoints</h2>
  <ul>
    <li><code>GET /</code> Dashboard UI</li>
    <li><code>GET /docs</code> This lightweight API reference</li>
    <li><code>POST /scan</code> Start a scan and stream SSE events</li>
    <li><code>GET /scans/&lt;scan_id&gt;</code> Scan job status</li>
    <li><code>GET /history</code> Saved scan history</li>
    <li><code>GET /history/compare?left_scan_id=...&amp;right_scan_id=...</code> Compare two saved scans</li>
    <li><code>GET /history/&lt;scan_id&gt;</code> Saved scan detail</li>
    <li><code>GET /history/&lt;scan_id&gt;/report</code> JSON report download</li>
    <li><code>GET /history/&lt;scan_id&gt;/report.md</code> Markdown report download</li>
    <li><code>GET /history/&lt;scan_id&gt;/report.html</code> HTML report download</li>
    <li><code>GET /health</code> Tool and queue health</li>
  </ul>
</body>
</html>"""
    return HttpResponse(body, content_type="text/html; charset=utf-8")


async def start_scan(request):
    if request.method != "POST":
        return HttpResponseNotAllowed(["POST"])

    try:
        payload = json.loads((request.body or b"{}").decode("utf-8"))
    except json.JSONDecodeError:
        return _json_error("Invalid JSON payload", 400)

    try:
        req = recon_api.ScanRequest(**payload)
    except ValidationError as exc:
        return JsonResponse({"detail": "Invalid scan payload", "errors": exc.errors()}, status=400)

    target = recon_api.normalize_target_input(req.target)
    if not target or not re.match(r"^[a-z0-9\-\.]+\.[a-z]{2,}$", target):
        return _json_error("Invalid target domain", 400)

    scope_error = recon_api.validate_target_scope(target)
    if scope_error:
        return _json_error(scope_error, 400)

    await recon_api.ensure_scan_workers()
    assert recon_api.scan_job_queue is not None

    modules = recon_api.merge_requested_modules(req.modules)
    profile = recon_api.resolve_scan_profile(req.scan_mode, req.ports)
    now = datetime.utcnow()
    last_started = recon_api.last_scan_times.get(target)
    min_gap = recon_api.APP_SETTINGS["min_seconds_between_scans"]
    if last_started and (now - last_started).total_seconds() < min_gap:
        return _json_error(f"Rate limit active for {target}. Wait a few seconds and try again.", 429)

    queued_jobs = sum(
        1 for item in recon_api.scans.values() if item.get("status") in {"queued", "running"}
    )
    if queued_jobs >= recon_api.APP_SETTINGS["max_pending_jobs"]:
        return _json_error("Scan queue is full. Wait for running jobs to finish.", 429)

    scan_id = uuid.uuid4().hex[:12]
    session_id = req.session_id or scan_id
    job = {
        "scan_id": scan_id,
        "session_id": session_id,
        "target": target,
        "profile": profile,
        "modules": modules,
        "wordlist": req.wordlist,
        "status": "queued",
        "started_at": now.isoformat(),
        "queue": asyncio.Queue(),
        "completed": False,
        "summary": None,
        "report": None,
    }
    recon_api.scans[scan_id] = job
    recon_api.last_scan_times[target] = now
    await recon_api.scan_job_queue.put(scan_id)

    async def event_stream():
        while True:
            try:
                event = await asyncio.wait_for(job["queue"].get(), timeout=1)
            except asyncio.TimeoutError:
                if job.get("completed"):
                    terminal_type = "complete" if str(job.get("status", "")).startswith("completed") else "fatal"
                    terminal_event = {
                        "type": terminal_type,
                        "scan_id": scan_id,
                        "session_id": session_id,
                        "scan_mode": profile["mode"],
                        "summary": job.get("summary"),
                        "saved": bool(job.get("report")),
                        "time": datetime.utcnow().isoformat(),
                    }
                    yield recon_api.sse_event(terminal_event)
                    break
                if recon_api.scan_worker_task is None or recon_api.scan_worker_task.done():
                    job["status"] = "failed"
                    job["completed"] = True
                    yield recon_api.sse_event(
                        {
                            "type": "fatal",
                            "scan_id": scan_id,
                            "session_id": session_id,
                            "msg": "Scan worker stopped before the job produced a terminal event.",
                            "level": "error",
                            "time": datetime.utcnow().isoformat(),
                        }
                    )
                    break
                continue

            yield recon_api.sse_event(event)
            if event.get("type") in {"complete", "fatal"}:
                break

    response = StreamingHttpResponse(event_stream(), content_type="text/event-stream")
    response["Cache-Control"] = "no-cache"
    response["X-Accel-Buffering"] = "no"
    return response


def scan_status(request, scan_id: str):
    if request.method != "GET":
        return HttpResponseNotAllowed(["GET"])

    job = recon_api.scans.get(scan_id)
    if not job:
        return _json_error("Scan job not found", 404)

    return JsonResponse(
        {
            "scan_id": job["scan_id"],
            "session_id": job["session_id"],
            "target": job["target"],
            "status": job["status"],
            "started_at": job["started_at"],
            "summary": job.get("summary"),
            "completed": bool(job.get("completed")),
        }
    )


def history(request):
    if request.method != "GET":
        return HttpResponseNotAllowed(["GET"])

    try:
        limit = int(request.GET.get("limit", "25"))
    except ValueError:
        return _json_error("limit must be an integer", 400)

    return JsonResponse({"items": recon_api.list_scan_records(limit=limit)})


def history_compare(request):
    if request.method != "GET":
        return HttpResponseNotAllowed(["GET"])

    left_scan_id = request.GET.get("left_scan_id", "")
    right_scan_id = request.GET.get("right_scan_id", "")
    if left_scan_id == right_scan_id:
        return _json_error("Choose two different saved scans to compare", 400)

    left_record = recon_api.get_scan_record(left_scan_id)
    right_record = recon_api.get_scan_record(right_scan_id)
    if not left_record or not right_record:
        return _json_error("One or both saved scans were not found", 404)

    return JsonResponse(recon_api.build_history_compare(left_record, right_record))


def history_detail(request, scan_id: str):
    if request.method != "GET":
        return HttpResponseNotAllowed(["GET"])

    record = recon_api.get_scan_record(scan_id)
    if not record:
        return _json_error("Saved scan not found", 404)

    return JsonResponse(record)


def history_report(request, scan_id: str):
    if request.method != "GET":
        return HttpResponseNotAllowed(["GET"])

    record = recon_api.get_scan_record(scan_id)
    if not record:
        return _json_error("Saved scan not found", 404)

    response = HttpResponse(
        json.dumps(record, indent=2),
        content_type="application/json",
    )
    response["Content-Disposition"] = f'attachment; filename="{_report_filename(record, "json")}"'
    return response


def history_report_markdown(request, scan_id: str):
    if request.method != "GET":
        return HttpResponseNotAllowed(["GET"])

    record = recon_api.get_scan_record(scan_id)
    if not record:
        return _json_error("Saved scan not found", 404)

    response = HttpResponse(
        recon_api.build_markdown_report(record),
        content_type="text/markdown",
    )
    response["Content-Disposition"] = f'attachment; filename="{_report_filename(record, "md")}"'
    return response


def history_report_html(request, scan_id: str):
    if request.method != "GET":
        return HttpResponseNotAllowed(["GET"])

    record = recon_api.get_scan_record(scan_id)
    if not record:
        return _json_error("Saved scan not found", 404)

    response = HttpResponse(
        recon_api.build_html_report(record),
        content_type="text/html",
    )
    response["Content-Disposition"] = f'attachment; filename="{_report_filename(record, "html")}"'
    return response


def health(request):
    if request.method != "GET":
        return HttpResponseNotAllowed(["GET"])

    tools = ["subfinder", "httpx", "nmap", "ffuf", "gau"]
    return JsonResponse(
        {
            "status": "ok",
            "version": "2.4.1",
            "framework": "django",
            "tools": {tool: recon_api.tool_status(tool) for tool in tools},
            "storage": {
                "engine": "sqlite3",
                "history_backend": recon_api.history_db_backend,
                "history_path": str(recon_api.HISTORY_DB_PATH),
            },
            "queue": {
                "pending_jobs": sum(
                    1 for item in recon_api.scans.values() if item.get("status") in {"queued", "running"}
                ),
                "rate_limit_seconds": recon_api.APP_SETTINGS["min_seconds_between_scans"],
            },
            "allowlist": recon_api.APP_SETTINGS["allowed_domains"],
        }
    )
