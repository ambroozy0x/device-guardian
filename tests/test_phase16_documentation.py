"""Phase 16 Automated Documentation Verification Test Suite.

Validates that:
1. All 18 documentation guides exist in docs/ and are non-empty.
2. Internal markdown cross-links resolve to real files on disk.
3. Critical operational caveats (24-hour soak status, Authenticode signing) are explicitly disclosed.
4. No real credentials, private keys, or bot tokens are leaked in docs.
5. Root README.md and CHANGELOG.md are synchronized with Phase 16 additions.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
DOCS_DIR = REPO_ROOT / "docs"

EXPECTED_DOC_FILES = [
    "README.md",
    "quick-start.md",
    "installation.md",
    "configuration.md",
    "operator-handbook.md",
    "security-guide.md",
    "detection-guide.md",
    "alerts-and-notifications.md",
    "reliability-and-soak.md",
    "troubleshooting.md",
    "recovery-and-backup.md",
    "updates-and-release.md",
    "deployment-checklist.md",
    "incident-response.md",
    "platform-support.md",
    "architecture.md",
    "faq.md",
    "known-limitations.md",
]


def test_docs_directory_exists():
    """Verify that docs/ directory exists and is a directory."""
    assert DOCS_DIR.is_dir(), f"Expected {DOCS_DIR} to exist as a directory"


def test_all_18_documentation_files_exist_and_non_empty():
    """Verify all 18 expected documentation files exist and have substantial content."""
    for filename in EXPECTED_DOC_FILES:
        doc_path = DOCS_DIR / filename
        assert doc_path.is_file(), f"Missing required documentation file: {filename}"
        size = doc_path.stat().st_size
        assert size > 500, f"Documentation file {filename} is suspiciously small ({size} bytes)"


def test_markdown_cross_links_resolve():
    """Verify that all relative markdown file links within docs/ point to actual existing files."""
    link_pattern = re.compile(r'\[([^\]]+)\]\(([^)]+)\)')

    broken_links = []

    for filename in EXPECTED_DOC_FILES:
        doc_path = DOCS_DIR / filename
        content = doc_path.read_text(encoding="utf-8")

        for match in link_pattern.finditer(content):
            url = match.group(2).strip()

            # Ignore external URLs, anchors, mailto, and file:/// URIs
            if (
                url.startswith("http://")
                or url.startswith("https://")
                or url.startswith("mailto:")
                or url.startswith("#")
                or url.startswith("file:///")
            ):
                continue

            # Strip anchor if present
            clean_url = url.split("#")[0]
            if not clean_url:
                continue

            # Resolve relative to the document
            target = (doc_path.parent / clean_url).resolve()
            if not target.exists():
                broken_links.append((filename, url, str(target)))

    assert not broken_links, f"Found broken relative links in docs: {broken_links}"


def test_critical_caveats_and_disclosures_present():
    """Verify that required operational disclosures are explicitly present in documentation."""
    # 1. 24-hour soak status: NOT RUN
    known_limitations = (DOCS_DIR / "known-limitations.md").read_text(encoding="utf-8")
    assert "24-Hour" in known_limitations or "24-hour" in known_limitations
    assert "NOT RUN" in known_limitations

    reliability_soak = (DOCS_DIR / "reliability-and-soak.md").read_text(encoding="utf-8")
    assert "24-HOUR" in reliability_soak or "24-hour" in reliability_soak or "24-Hour" in reliability_soak
    assert "NOT RUN" in reliability_soak

    # 2. Windows Authenticode signing: NOT VERIFIED / NOT IMPLEMENTED
    assert "Authenticode" in known_limitations
    assert "NOT VERIFIED" in known_limitations or "NOT IMPLEMENTED" in known_limitations

    updates_doc = (DOCS_DIR / "updates-and-release.md").read_text(encoding="utf-8")
    assert "Authenticode" in updates_doc
    assert "NOT VERIFIED" in updates_doc or "NOT IMPLEMENTED" in updates_doc

    security_doc = (DOCS_DIR / "security-guide.md").read_text(encoding="utf-8")
    assert "Authenticode" in security_doc


def test_zero_real_secrets_in_docs():
    """Ensure no real bot tokens or private key banners exist in documentation."""
    # Real Telegram bot token pattern: 8-10 digits:35 alphanumeric/dash/underscore
    token_pattern = re.compile(r'\b\d{9,10}:[A-Za-z0-9_-]{35}\b')
    private_key_pattern = re.compile(r'-----BEGIN\s+(?:RSA\s+)?PRIVATE\s+KEY-----')

    scanned_files = list(DOCS_DIR.glob("*.md")) + [REPO_ROOT / "README.md", REPO_ROOT / "CHANGELOG.md"]

    for doc_path in scanned_files:
        content = doc_path.read_text(encoding="utf-8")
        assert not private_key_pattern.search(content), f"Private key header leaked in {doc_path.name}"

        matches = token_pattern.findall(content)
        # Verify no token is real (dummy tokens with 'EXAMPLE' or repetitive characters are fine)
        for m in matches:
            assert "EXAMPLE" in m or "dummy" in m.lower(), f"Suspicious real-looking bot token in {doc_path.name}: {m}"


def test_root_readme_and_changelog_sync():
    """Verify that root README.md and CHANGELOG.md reference Phase 16 and documentation."""
    readme_content = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "Phase 16" in readme_content
    assert "docs/operator-handbook.md" in readme_content
    assert "docs/known-limitations.md" in readme_content

    changelog_content = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "Phase 16" in changelog_content
    assert "docs/quick-start.md" in changelog_content
