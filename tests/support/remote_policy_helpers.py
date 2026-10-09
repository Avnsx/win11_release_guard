"""Helpers shared by the test_remote_policy test modules."""

from __future__ import annotations

from win11_release_guard.config import DEFAULT_PUBLISHED_POLICY_URLS, DEFAULT_RELEASE_HEALTH_URL


def _fixture_html() -> str:
    with open("tests/fixtures/windows11-release-health.html", encoding="utf-8") as handle:
        return handle.read()


def _fixture_html_file(name: str) -> str:
    with open(f"tests/fixtures/{name}", encoding="utf-8") as handle:
        return handle.read()


def _json_policy() -> dict:
    return {
        "schema_version": 1,
        "generated_at_utc": "2026-05-28T00:00:00Z",
        "source_urls": [
            DEFAULT_RELEASE_HEALTH_URL,
        ],
        "published_urls": dict(DEFAULT_PUBLISHED_POLICY_URLS),
        "source": {"generator": "test"},
        "current_versions": [
            {
                "version": "24H2",
                "build_family": 26100,
                "latest_build": "26100.8457",
                "servicing_option": "General Availability Channel",
            },
            {
                "version": "25H2",
                "build_family": 26200,
                "latest_build": "26200.8457",
                "baseline_build": "26200.8457",
                "servicing_option": "General Availability Channel",
            },
        ],
        "supported_build_families": {
            "26100": "24H2",
            "26200": "25H2",
        },
        "broad_target_existing_devices": {
            "version": "25H2",
            "build_family": 26200,
            "latest_build": "26200.8457",
            "baseline_build": "26200.8457",
            "servicing_option": "General Availability Channel",
        },
        "release_history": [
            {
                "release": "25H2",
                "build_family": 26200,
                "build": "26200.8457",
                "availability_date": "2026-05-12",
                "servicing_option": "General Availability Channel",
                "update_type": "2026-05 B",
                "update_type_letter": "B",
                "kb_article": "KB5089549",
            }
        ],
    }


PENDING_26H2_FIXTURE = "windows11-release-health-26h2-pending-b.html"


def _pending_26h2_html() -> str:
    return _fixture_html_file(PENDING_26H2_FIXTURE)
