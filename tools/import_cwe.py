#!/usr/bin/env python3
"""Import an official CWE XML distribution into an agent-friendly, versioned data pack.

The importer never downloads content. Fetch an official release archive separately,
record its SHA-256, and pass its local path with --archive. This makes updates
reviewable and reproducible.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import zipfile
from datetime import date
from pathlib import Path
from typing import Any
from xml.etree import ElementTree as ET


ROOT = Path(__file__).resolve().parents[1]
SOURCE_URL = "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip"
TERMS_URL = "https://cwe.mitre.org/about/termsofuse.html"


def local_name(name: str) -> str:
    """Return an XML local name without its namespace."""
    return name.rsplit("}", 1)[-1]


def normalized_text(value: str | None) -> str | None:
    if value is None:
        return None
    normalized = " ".join(value.split())
    return normalized or None


def element_to_object(element: ET.Element) -> dict[str, Any]:
    """Losslessly preserve element names, attributes, text, and ordered children."""
    result: dict[str, Any] = {"tag": local_name(element.tag)}
    if element.attrib:
        result["attributes"] = dict(sorted(element.attrib.items()))
    text = normalized_text(element.text)
    if text:
        result["text"] = text
    children = [element_to_object(child) for child in element]
    if children:
        result["children"] = children
    return result


def first_child_text(element: ET.Element, tag_name: str) -> str | None:
    for child in element.iter():
        if local_name(child.tag) == tag_name:
            text = " ".join(part.strip() for part in child.itertext() if part.strip())
            if text:
                return text
    return None


def summary_for(element: ET.Element) -> str | None:
    for tag_name in ("Description", "Summary", "Extended_Description"):
        summary = first_child_text(element, tag_name)
        if summary:
            return summary
    return None


def catalog_item(element: ET.Element, item_type: str) -> dict[str, Any]:
    attributes = element.attrib
    item: dict[str, Any] = {
        "id": f"CWE-{attributes['ID']}",
        "type": item_type,
        "name": attributes.get("Name", ""),
        "status": attributes.get("Status", ""),
        "summary": summary_for(element),
        "content": element_to_object(element),
    }
    for field in ("Abstraction", "Structure"):
        if field in attributes:
            item[field.lower()] = attributes[field]
    return item


def relationships_from(element: ET.Element, source_id: str) -> list[dict[str, str]]:
    relationships: list[dict[str, str]] = []
    for child in element.iter():
        child_name = local_name(child.tag)
        attributes = child.attrib
        target_id = attributes.get("CWE_ID") or attributes.get("ID")
        if child_name == "Related_Weakness" and target_id:
            relationship = {"source": source_id, "target": f"CWE-{target_id}", "kind": attributes.get("Nature", "related")}
            if "View_ID" in attributes:
                relationship["view_id"] = f"CWE-{attributes['View_ID']}"
            relationships.append(relationship)
        elif child_name == "Has_Member" and target_id:
            relationships.append({"source": source_id, "target": f"CWE-{target_id}", "kind": "has_member"})
    return relationships


def archive_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        while chunk := handle.read(1_048_576):
            digest.update(chunk)
    return digest.hexdigest()


def extract_xml(archive: Path) -> bytes:
    if not zipfile.is_zipfile(archive):
        raise ValueError("archive must be a ZIP file")
    with zipfile.ZipFile(archive) as zip_file:
        xml_members = [member for member in zip_file.infolist() if member.filename.lower().endswith(".xml") and not member.is_dir()]
        if len(xml_members) != 1:
            raise ValueError("archive must contain exactly one XML file")
        member = xml_members[0]
        if member.file_size > 100_000_000:
            raise ValueError("XML file is larger than the 100 MB import safety limit")
        return zip_file.read(member)


def write_json(path: Path, value: Any) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, separators=(",", ":")) + "\n", encoding="utf-8")


def import_archive(archive: Path, output_dir: Path) -> dict[str, Any]:
    xml_bytes = extract_xml(archive)
    root = ET.fromstring(xml_bytes)
    if local_name(root.tag) != "Weakness_Catalog":
        raise ValueError("XML root is not Weakness_Catalog")

    groups = {
        "Weaknesses": ("weakness", "weaknesses"),
        "Categories": ("category", "categories"),
        "Views": ("view", "views"),
        "External_References": ("external_reference", "external_references"),
    }
    catalog: dict[str, Any] = {
        "format": "agentsec-cwe-catalog/v1",
        "source": {"url": SOURCE_URL, "terms": TERMS_URL},
        "catalog_metadata": dict(sorted(root.attrib.items())),
    }
    index: list[dict[str, Any]] = []
    relationships: list[dict[str, str]] = []
    counts: dict[str, int] = {}

    root_children = {local_name(child.tag): child for child in root}
    for xml_group, (item_type, output_group) in groups.items():
        group = root_children.get(xml_group)
        items: list[dict[str, Any]] = []
        if group is not None:
            for element in group:
                if xml_group == "External_References":
                    object_value = element_to_object(element)
                    reference_id = element.attrib.get("Reference_ID", "")
                    items.append({"id": reference_id, "content": object_value})
                    continue
                item = catalog_item(element, item_type)
                items.append(item)
                index.append({
                    "id": item["id"], "type": item["type"], "name": item["name"],
                    "status": item["status"], "summary": item["summary"],
                    "abstraction": item.get("abstraction"), "structure": item.get("structure"),
                })
                relationships.extend(relationships_from(element, item["id"]))
        catalog[output_group] = items
        counts[output_group] = len(items)

    version = root.attrib.get("Version", "unknown")
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest = {
        "format": "agentsec-cwe-manifest/v1",
        "cwe_version": version,
        "catalog_date": root.attrib.get("Date"),
        "schema_location": root.attrib.get("{http://www.w3.org/2001/XMLSchema-instance}schemaLocation"),
        "source_url": SOURCE_URL,
        "terms_url": TERMS_URL,
        "source_archive_sha256": archive_sha256(archive),
        "source_xml_sha256": hashlib.sha256(xml_bytes).hexdigest(),
        "imported_on": date.today().isoformat(),
        "counts": counts,
        "generator": "tools/import_cwe.py",
    }
    write_json(output_dir / "catalog.json", catalog)
    write_json(output_dir / "index.json", {"format": "agentsec-cwe-index/v1", "entries": index})
    write_json(output_dir / "relationships.json", {"format": "agentsec-cwe-relationships/v1", "relationships": relationships})
    write_json(output_dir / "manifest.json", manifest)
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True, type=Path, help="official CWE XML ZIP archive")
    parser.add_argument("--output", type=Path, help="output data-pack directory; defaults to data/cwe/<version>")
    args = parser.parse_args()
    try:
        xml_bytes = extract_xml(args.archive)
        root = ET.fromstring(xml_bytes)
        version = root.attrib.get("Version", "unknown")
        output = args.output or ROOT / "data" / "cwe" / version
        manifest = import_archive(args.archive, output)
        print(json.dumps({"output": str(output), **manifest}, indent=2, sort_keys=True))
        return 0
    except (OSError, ET.ParseError, ValueError, zipfile.BadZipFile) as exc:
        print(f"import-cwe: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
