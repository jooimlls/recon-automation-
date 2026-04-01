import asyncio
import json
import os
import unittest

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "reconsite.settings")

import django

django.setup()

from django.test import AsyncClient, Client


class ReconDjangoSmokeTests(unittest.TestCase):
    def setUp(self):
        self.client = Client()

    def test_dashboard_and_health_routes_work(self):
        dashboard = self.client.get("/")
        self.assertEqual(dashboard.status_code, 200)
        self.assertIn("text/html", dashboard["Content-Type"])

        health = self.client.get("/health")
        self.assertEqual(health.status_code, 200)
        payload = health.json()
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["framework"], "django")


class ReconDjangoStreamingTests(unittest.IsolatedAsyncioTestCase):
    async def test_scan_stream_completes_with_all_modules_disabled(self):
        client = AsyncClient()
        response = await client.post(
            "/scan",
            data=json.dumps(
                {
                    "target": "example.com",
                    "modules": {
                        "subdomain": False,
                        "dns": False,
                        "port": False,
                        "fingerprint": False,
                        "js": False,
                        "url_intel": False,
                        "dir": False,
                    },
                }
            ),
            content_type="application/json",
        )
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/event-stream", response["Content-Type"])

        chunks = []
        async for chunk in response.streaming_content:
            chunks.append(chunk.decode() if isinstance(chunk, (bytes, bytearray)) else str(chunk))

        body = "".join(chunks)
        self.assertIn("data:", body)
        self.assertIn('"type": "complete"', body)
