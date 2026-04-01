from django.urls import path

from . import views


urlpatterns = [
    path("", views.dashboard, name="dashboard"),
    path("docs", views.docs, name="docs"),
    path("scan", views.start_scan, name="scan"),
    path("scans/<str:scan_id>", views.scan_status, name="scan-status"),
    path("history", views.history, name="history"),
    path("history/compare", views.history_compare, name="history-compare"),
    path("history/<str:scan_id>", views.history_detail, name="history-detail"),
    path("history/<str:scan_id>/report", views.history_report, name="history-report"),
    path("history/<str:scan_id>/report.md", views.history_report_markdown, name="history-report-markdown"),
    path("history/<str:scan_id>/report.html", views.history_report_html, name="history-report-html"),
    path("health", views.health, name="health"),
]
