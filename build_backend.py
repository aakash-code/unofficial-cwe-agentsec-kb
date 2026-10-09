"""Minimal dependency-free PEP 517 backend for AgentSec KB.

The project intentionally has no runtime dependencies. Keeping this backend in
the repository lets users build a wheel in restricted or offline environments.
"""

from __future__ import annotations

import base64
import hashlib
from pathlib import Path
import zipfile


NAME = "agentsec_kb"
VERSION = "0.3.0"
DIST_INFO = f"{NAME}-{VERSION}.dist-info"
ROOT = Path(__file__).resolve().parent
INCLUDED_DIRECTORIES = ("tools", "knowledge", "mappings", "schemas", "policies", "data", "vendor")
INCLUDED_FILES = ("LICENSE", "NOTICE", "CREDITS.md", "SOURCES.md")
# Everything installs under one package so generic names like tools/ and data/ never land at the top of
# site-packages. tools/agentsec.py finds its data relative to itself, so the nesting needs no code change.
PACKAGE = NAME
ENTRY_POINTS = f"[console_scripts]\nagentsec = {PACKAGE}.tools.agentsec:main\n"


def _metadata() -> str:
    return "\n".join((
        "Metadata-Version: 2.1",
        "Name: agentsec-kb",
        f"Version: {VERSION}",
        "Summary: Vendor-neutral secure-development knowledge base for coding agents",
        "Requires-Python: >=3.10",
        "License: MIT",
        "",
    ))


def _wheel() -> str:
    return "\n".join((
        "Wheel-Version: 1.0",
        "Generator: agentsec-kb build_backend",
        "Root-Is-Purelib: true",
        "Tag: py3-none-any",
        "",
    ))


def _record_line(path: str, data: bytes) -> str:
    digest = base64.urlsafe_b64encode(hashlib.sha256(data).digest()).decode("ascii").rstrip("=")
    return f"{path},sha256={digest},{len(data)}"


def _write_metadata(target: Path) -> str:
    dist_info = target / DIST_INFO
    dist_info.mkdir(parents=True, exist_ok=True)
    (dist_info / "METADATA").write_text(_metadata(), encoding="utf-8")
    (dist_info / "WHEEL").write_text(_wheel(), encoding="utf-8")
    (dist_info / "entry_points.txt").write_text(ENTRY_POINTS, encoding="utf-8")
    return DIST_INFO


def get_requires_for_build_wheel(config_settings=None):  # noqa: ANN001, D103
    return []


def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):  # noqa: ANN001, D103
    return _write_metadata(Path(metadata_directory))


def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):  # noqa: ANN001, D103
    filename = f"{NAME}-{VERSION}-py3-none-any.whl"
    wheel_path = Path(wheel_directory) / filename
    entries: dict[str, bytes] = {}
    for directory in INCLUDED_DIRECTORIES:
        for source_path in sorted((ROOT / directory).rglob("*")):
            if source_path.is_file() and "__pycache__" not in source_path.parts:
                entries[f"{PACKAGE}/{source_path.relative_to(ROOT).as_posix()}"] = source_path.read_bytes()
    for relative_path in INCLUDED_FILES:
        entries[f"{PACKAGE}/{relative_path}"] = (ROOT / relative_path).read_bytes()
    entries[f"{PACKAGE}/__init__.py"] = b'"""Unofficial CWE AgentSec KB data and tools."""\n'
    entries[f"{DIST_INFO}/licenses/LICENSE"] = (ROOT / "LICENSE").read_bytes()
    entries[f"{DIST_INFO}/METADATA"] = _metadata().encode("utf-8")
    entries[f"{DIST_INFO}/WHEEL"] = _wheel().encode("utf-8")
    entries[f"{DIST_INFO}/entry_points.txt"] = ENTRY_POINTS.encode("utf-8")
    record = [_record_line(path, data) for path, data in entries.items()]
    record.append(f"{DIST_INFO}/RECORD,,")
    entries[f"{DIST_INFO}/RECORD"] = ("\n".join(record) + "\n").encode("utf-8")
    with zipfile.ZipFile(wheel_path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        for path, data in entries.items():
            archive.writestr(path, data)
    return filename


def build_sdist(sdist_directory, config_settings=None):  # noqa: ANN001, D103
    raise RuntimeError("Source distributions are not implemented; use the repository checkout or build_wheel.")
