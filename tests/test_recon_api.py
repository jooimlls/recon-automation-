import json
import socket
import unittest
from unittest.mock import patch

import recon_api


class ReconApiHelperTests(unittest.TestCase):
    def test_normalize_target_input_strips_scheme_path_and_port(self):
        self.assertEqual(
            recon_api.normalize_target_input("https://Example.com:8443/login"),
            "example.com",
        )
        self.assertEqual(
            recon_api.normalize_target_input("sub.example.com/path/to/page"),
            "sub.example.com",
        )

    def test_filter_subdomain_candidates_keeps_only_valid_children(self):
        candidates = [
            "api.example.com",
            "API.EXAMPLE.COM",
            "example.com",
            "https://dev.example.com/dashboard",
            "The command you've entered",
            "admin.evil.com",
        ]
        valid, ignored = recon_api.filter_subdomain_candidates(candidates, "example.com")
        self.assertEqual(valid, ["api.example.com", "dev.example.com"])
        self.assertEqual(ignored, 3)

    def test_sse_event_wraps_json_payload(self):
        payload = {"type": "start", "target": "example.com"}
        event = recon_api.sse_event(payload)
        self.assertTrue(event.startswith("data: "))
        self.assertTrue(event.endswith("\n\n"))
        encoded = event[len("data: "):-2]
        self.assertEqual(json.loads(encoded), payload)

    def test_redaction_helpers_mask_sensitive_values(self):
        self.assertTrue(recon_api.finding_is_sensitive("API_KEY"))
        self.assertFalse(recon_api.finding_is_sensitive("GRAPHQL"))
        self.assertEqual(recon_api.redact_sensitive_value(""), "[redacted]")
        self.assertEqual(
            recon_api.redact_sensitive_value("-----BEGIN PRIVATE KEY-----"),
            "[private key redacted]",
        )
        self.assertEqual(
            recon_api.redact_sensitive_value("ABCDEFGHIJKLMNOPQRST"),
            "ABCD...QRST",
        )


class ReconApiFallbackTests(unittest.IsolatedAsyncioTestCase):
    async def test_run_subdomain_enum_uses_dns_fallback_when_tools_missing(self):
        profile = recon_api.resolve_scan_profile("fast", None)

        def fake_gethostbyname(host: str) -> str:
            if host == "api.example.com":
                return "1.2.3.4"
            raise socket.gaierror()

        with patch("recon_api.tool_available", return_value=False), patch(
            "recon_api.resolve_httpx_command", return_value=None
        ), patch("recon_api.socket.gethostbyname", side_effect=fake_gethostbyname):
            events = [event async for event in recon_api.run_subdomain_enum("example.com", profile)]

        result_events = [event for event in events if event.get("type") == "result"]
        done_events = [event for event in events if event.get("type") == "done"]

        self.assertEqual(len(result_events), 1)
        self.assertEqual(result_events[0]["data"]["name"], "api.example.com")
        self.assertEqual(result_events[0]["data"]["source"], "dns fallback")
        self.assertEqual(result_events[0]["data"]["status"], "live")
        self.assertEqual(done_events[0]["count"], 1)


if __name__ == "__main__":
    unittest.main()
