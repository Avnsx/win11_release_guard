from __future__ import annotations

import pytest
import win11_release_guard.policy_generator as policy_generator_module
from tests.support.policy_generator_helpers import FAKE_MSRC_CVRF_WITHOUT_KB5094126, FAKE_MSRC_CVRF_WITH_KB5094126


def test_msrc_cvrf_kb_join_collects_cves_severities_and_products() -> None:
    result = policy_generator_module._cvrf_kb_join(FAKE_MSRC_CVRF_WITH_KB5094126, "KB5094126")

    assert result == {
        "is_security": True,
        "cves": ["CVE-2026-0001", "CVE-2026-0002"],
        "severities": ["Critical", "Important"],
        "products": ["11568", "11569", "11570"],
        "client_products": [],
        "evidence_source": "msrc_cvrf",
    }


def test_msrc_cvrf_kb_join_minimal_exact_kb_remediation_is_security() -> None:
    result = policy_generator_module._cvrf_kb_join(
        {
            "Vulnerability": [
                {
                    "Remediations": [
                        {"Description": {"Value": "Security Update for KB5094126"}},
                    ],
                }
            ]
        },
        "KB5094126",
    )

    assert result == {
        "is_security": True,
        "cves": [],
        "severities": [],
        "products": [],
        "client_products": [],
        "evidence_source": "msrc_cvrf",
    }


def test_msrc_cvrf_kb_join_caps_large_context_lists_deterministically() -> None:
    vulnerabilities = []
    for index in range(20, 0, -1):
        vulnerabilities.append(
            {
                "CVE": f"CVE-2026-{index:04d}",
                "Threats": [{"Type": "Severity", "Description": {"Value": f"Severity {index:02d}"}}],
                "Remediations": [
                    {
                        "Description": {"Value": "Security Update for KB5094126"},
                        "ProductID": [f"P{index:03d}", f"P{index + 100:03d}"],
                    }
                ],
            }
        )

    result = policy_generator_module._cvrf_kb_join({"Vulnerability": vulnerabilities}, "KB5094126")

    assert result["is_security"] is True
    assert result["evidence_source"] == "msrc_cvrf"
    assert result["cves"] == [f"CVE-2026-{index:04d}" for index in range(1, 13)]
    assert result["severities"] == [f"Severity {index:02d}" for index in range(1, 9)]
    assert result["products"] == [f"P{index:03d}" for index in range(1, 17)]


def _fake_cvrf_with_remediation_text(text: str) -> dict[str, object]:
    return {
        "Vulnerability": [
            {
                "CVE": "CVE-2026-1234",
                "Threats": [{"Type": "Severity", "Description": {"Value": "Important"}}],
                "Remediations": [{"Description": {"Value": text}, "ProductID": ["11568"]}],
            }
        ]
    }


@pytest.mark.parametrize(
    "text",
    (
        "Security Update for KB5094126",
        "https://catalog.update.microsoft.com/Search.aspx?q=KB5094126",
        "Article 5094126",
    ),
)
def test_msrc_cvrf_kb_join_matches_exact_kb_tokens(text: str) -> None:
    result = policy_generator_module._cvrf_kb_join(_fake_cvrf_with_remediation_text(text), "5094126")

    assert result["is_security"] is True
    assert result["cves"] == ["CVE-2026-1234"]
    assert result["evidence_source"] == "msrc_cvrf"


@pytest.mark.parametrize(
    "text",
    (
        "Security Update for KB15094126",
        "Security Update for KB50941260",
        "Security Update for 15094126",
        "Security Update for 5094126a",
        "https://catalog.update.microsoft.com/Search.aspx?q=KB50941260",
        "https://catalog.update.microsoft.com/Search.aspx?q=KB5094127",
    ),
)
def test_msrc_cvrf_kb_join_rejects_substring_false_positives(text: str) -> None:
    result = policy_generator_module._cvrf_kb_join(_fake_cvrf_with_remediation_text(text), "KB5094126")

    assert result == {
        "is_security": False,
        "cves": [],
        "severities": [],
        "products": [],
        "client_products": [],
        "evidence_source": "none",
    }


def test_msrc_cvrf_kb_join_malformed_payload_is_unknown_not_false() -> None:
    result = policy_generator_module._cvrf_kb_join(["not", "a", "mapping"], "KB5094126")  # type: ignore[arg-type]

    assert result == {
        "is_security": None,
        "cves": [],
        "severities": [],
        "products": [],
        "client_products": [],
        "evidence_source": "unavailable",
    }


def test_msrc_cvrf_kb_absent_is_not_security() -> None:
    result = policy_generator_module._cvrf_kb_join(FAKE_MSRC_CVRF_WITHOUT_KB5094126, "KB5094126")

    assert result == {
        "is_security": False,
        "cves": [],
        "severities": [],
        "products": [],
        "client_products": [],
        "evidence_source": "none",
    }


FAKE_MSRC_CVRF_WITH_PRODUCT_TREE = {
    "ProductTree": {
        "Branch": [
            {
                "Type": "Vendor",
                "Name": "Microsoft",
                "Items": [
                    {
                        "Type": "Product Family",
                        "Name": "Windows",
                        "Items": [
                            {
                                "ProductID": "11568",
                                "Value": "Windows 11 Version 25H2 for x64-based Systems",
                            },
                            {
                                "ProductID": "11569",
                                "Value": "Windows 11 Version 24H2 for ARM64-based Systems",
                            },
                            {
                                "ProductID": "11650-10378",
                                "Value": "Windows Server 2025 (Server Core installation)",
                            },
                        ],
                    }
                ],
            }
        ],
        "FullProductName": [
            {"ProductID": "11568", "Value": "Windows 11 Version 25H2 for x64-based Systems"},
        ],
    },
    "Vulnerability": [
        {
            "CVE": "CVE-2026-0001",
            "Threats": [{"Type": "Severity", "Description": {"Value": "Important"}}],
            "Remediations": [
                {
                    "Description": {"Value": "Security Update for KB5101650"},
                    "ProductID": ["11650-10378", "11569", "11568"],
                    "Supercedence": "5101650",
                }
            ],
        },
        {
            "CVE": "CVE-2026-0002",
            "Threats": [{"Type": "Severity", "Description": {"Value": "Critical"}}],
            "Remediations": [
                {
                    "Description": {"Value": "Security Update for KB5101650"},
                    "ProductID": ["11568", "11569", "11650-10378"],
                }
            ],
        },
    ],
}


def test_msrc_cvrf_kb_join_reports_product_names_and_client_products() -> None:
    result = policy_generator_module._cvrf_kb_join(FAKE_MSRC_CVRF_WITH_PRODUCT_TREE, "KB5101650")

    assert result == {
        "is_security": True,
        "cves": ["CVE-2026-0001", "CVE-2026-0002"],
        "severities": ["Critical", "Important"],
        "products": [
            "Windows 11 Version 24H2 for ARM64-based Systems",
            "Windows 11 Version 25H2 for x64-based Systems",
            "Windows Server 2025 (Server Core installation)",
        ],
        "client_products": [
            "Windows 11 Version 24H2 for ARM64-based Systems",
            "Windows 11 Version 25H2 for x64-based Systems",
        ],
        "evidence_source": "msrc_cvrf",
    }


def test_msrc_cvrf_product_names_survive_branch_nodes_without_value() -> None:
    names = policy_generator_module._cvrf_product_names_by_id(FAKE_MSRC_CVRF_WITH_PRODUCT_TREE)

    assert names["11568"] == "Windows 11 Version 25H2 for x64-based Systems"
    assert names["11650-10378"] == "Windows Server 2025 (Server Core installation)"
    assert "Microsoft" not in set(names.values())
    assert "Windows" not in set(names.values())


def test_msrc_cvrf_product_names_tolerate_cyclic_product_tree() -> None:
    branch: dict[str, object] = {"Type": "Vendor", "Name": "Microsoft"}
    branch["Items"] = [
        branch,
        {"ProductID": "11568", "Value": "Windows 11 Version 25H2 for x64-based Systems"},
    ]

    names = policy_generator_module._cvrf_product_names_by_id({"ProductTree": {"Branch": [branch]}})

    assert names == {"11568": "Windows 11 Version 25H2 for x64-based Systems"}


def test_msrc_cvrf_kb_join_keeps_unknown_product_ids_and_self_supercedence_stable() -> None:
    payload = {
        "Vulnerability": [
            {
                "CVE": "CVE-2026-0003",
                "Remediations": [
                    {
                        "Description": {"Value": "Security Update for KB5101649"},
                        "ProductID": ["11570", "11570"],
                        "Supercedence": "5101649",
                    }
                ],
            }
        ]
    }

    result = policy_generator_module._cvrf_kb_join(payload, "KB5101649")

    assert result["is_security"] is True
    assert result["products"] == ["11570"]
    assert result["client_products"] == []


def test_msrc_cvrf_client_product_names_filters_to_windows_11() -> None:
    names = (
        "Windows 11 Version 25H2 for x64-based Systems",
        "windows 11 version 24h2 for arm64-based systems",
        "Windows Server 2025",
        "Windows 10 Version 22H2",
    )

    assert policy_generator_module._cvrf_client_product_names(names) == (
        "Windows 11 Version 25H2 for x64-based Systems",
        "windows 11 version 24h2 for arm64-based systems",
    )
