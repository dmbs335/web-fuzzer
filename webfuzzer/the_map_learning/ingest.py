from __future__ import annotations

from dataclasses import dataclass, field
import re
from pathlib import Path


HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
SECTION_RE = re.compile(r"^§(?P<ref>\d+(?:-\d+)?)\.\s+(?P<title>.+)$")
APPENDIX_HINTS = (
    "attack scenario mapping",
    "cve / bounty mapping",
    "cve/bounty mapping",
    "cve mapping",
    "detection & testing tools",
    "detection tools",
    "summary: core principles",
    "references",
)


@dataclass
class Block:
    kind: str
    level: int = 0
    text: str = ""
    rows: list[dict[str, str]] = field(default_factory=list)


def slugify(value: str) -> str:
    value = value.lower().strip()
    value = re.sub(r"[^a-z0-9]+", "-", value)
    return value.strip("-")


def clean_inline_markdown(value: str) -> str:
    value = value.strip()
    value = value.replace("**", "")
    value = value.replace("__", "")
    value = value.replace("`", "")
    value = re.sub(r"\[(.*?)\]\([^)]+\)", r"\1", value)
    value = re.sub(r"<br\s*/?>", " ", value, flags=re.IGNORECASE)
    value = re.sub(r"\s+", " ", value)
    return value.strip()


def is_table_line(line: str) -> bool:
    stripped = line.strip()
    return stripped.startswith("|") and stripped.endswith("|")


def is_separator_row(line: str) -> bool:
    cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
    if not cells:
        return False
    return all(re.fullmatch(r":?-{3,}:?", cell) for cell in cells)


def parse_table(lines: list[str]) -> list[dict[str, str]]:
    if len(lines) < 2:
        return []
    header = [clean_inline_markdown(cell) for cell in lines[0].strip().strip("|").split("|")]
    body_lines = lines[2:] if is_separator_row(lines[1]) else lines[1:]
    rows: list[dict[str, str]] = []
    for line in body_lines:
        cells = [clean_inline_markdown(cell) for cell in line.strip().strip("|").split("|")]
        if not any(cells):
            continue
        padded = cells + [""] * max(0, len(header) - len(cells))
        row = {header[idx]: padded[idx] for idx in range(min(len(header), len(padded)))}
        rows.append(row)
    return rows


def parse_blocks(markdown: str) -> list[Block]:
    lines = markdown.splitlines()
    blocks: list[Block] = []
    i = 0
    while i < len(lines):
        line = lines[i].rstrip()
        stripped = line.strip()
        if not stripped:
            i += 1
            continue

        heading_match = HEADING_RE.match(stripped)
        if heading_match:
            blocks.append(
                Block(
                    kind="heading",
                    level=len(heading_match.group(1)),
                    text=clean_inline_markdown(heading_match.group(2)),
                )
            )
            i += 1
            continue

        if is_table_line(stripped):
            table_lines = [stripped]
            i += 1
            while i < len(lines) and is_table_line(lines[i].strip()):
                table_lines.append(lines[i].strip())
                i += 1
            rows = parse_table(table_lines)
            if rows:
                blocks.append(Block(kind="table", rows=rows))
            continue

        if stripped.startswith("- ") or stripped.startswith("* "):
            blocks.append(Block(kind="paragraph", text=clean_inline_markdown(stripped)))
            i += 1
            continue

        paragraph_lines = [stripped]
        i += 1
        while i < len(lines):
            candidate = lines[i].rstrip()
            candidate_stripped = candidate.strip()
            if not candidate_stripped:
                i += 1
                break
            if HEADING_RE.match(candidate_stripped) or is_table_line(candidate_stripped):
                break
            paragraph_lines.append(candidate_stripped)
            i += 1
        blocks.append(Block(kind="paragraph", text=clean_inline_markdown(" ".join(paragraph_lines))))
    return blocks


def heading_text(block: Block) -> str:
    return block.text.lower()


def extract_axis_summary(paragraphs: list[str], axis_number: int) -> str | None:
    marker = f"axis {axis_number}"
    for paragraph in paragraphs:
        if marker in paragraph.lower():
            return paragraph
    return None


def extract_overview(blocks: list[Block]) -> dict[str, object]:
    overview = {
        "classification_structure": [],
        "axis_summaries": {"axis1": None, "axis2": None, "axis3": None},
        "discrepancy_types": [],
    }
    inside_classification = False
    for idx, block in enumerate(blocks):
        if block.kind == "heading" and block.level == 2 and block.text.lower() == "classification structure":
            inside_classification = True
            continue
        if inside_classification and block.kind == "heading" and block.level == 2:
            break
        if inside_classification and block.kind == "paragraph":
            overview["classification_structure"].append(block.text)
        if inside_classification and block.kind == "table":
            prior_heading = ""
            for probe in range(idx - 1, -1, -1):
                candidate = blocks[probe]
                if candidate.kind == "heading" and candidate.level == 3:
                    prior_heading = candidate.text.lower()
                    break
            if "axis 2" in prior_heading or any("description" in row for row in block.rows):
                for row in block.rows:
                    overview["discrepancy_types"].append(
                        {
                            "code": row.get("Code"),
                            "name": row.get("Discrepancy Type") or row.get("Name") or row.get("Subtype") or "",
                            "description": row.get("Description", ""),
                            "primary_sections": [
                                item.strip()
                                for item in row.get("Primary Sections", "").split(",")
                                if item.strip()
                            ],
                        }
                    )
    paragraphs: list[str] = overview["classification_structure"]  # type: ignore[assignment]
    axis_summaries = overview["axis_summaries"]  # type: ignore[assignment]
    axis_summaries["axis1"] = extract_axis_summary(paragraphs, 1)
    axis_summaries["axis2"] = extract_axis_summary(paragraphs, 2)
    axis_summaries["axis3"] = extract_axis_summary(paragraphs, 3)
    return overview


def parse_section_heading(text: str) -> tuple[str, str] | None:
    match = SECTION_RE.match(text)
    if not match:
        return None
    return match.group("ref"), clean_inline_markdown(match.group("title"))


def is_appendix_heading(text: str) -> bool:
    lowered = text.lower()
    return any(hint in lowered for hint in APPENDIX_HINTS)


def extract_axis1_and_appendices(blocks: list[Block]) -> tuple[list[dict[str, object]], dict[str, list[object]]]:
    axis_sections: list[dict[str, object]] = []
    appendices: dict[str, list[object]] = {
        "scenario_mapping": [],
        "case_studies": [],
        "tools": [],
        "principles": [],
        "references": [],
    }

    current_section: dict[str, object] | None = None
    current_subsection: dict[str, object] | None = None
    current_appendix: str | None = None

    for block in blocks:
        if block.kind == "heading" and block.level == 2:
            if is_appendix_heading(block.text):
                current_section = None
                current_subsection = None
                lower = block.text.lower()
                if "attack scenario mapping" in lower:
                    current_appendix = "scenario_mapping"
                elif "cve" in lower:
                    current_appendix = "case_studies"
                elif "detection" in lower:
                    current_appendix = "tools"
                elif "summary: core principles" in lower:
                    current_appendix = "principles"
                elif "references" in lower:
                    current_appendix = "references"
                else:
                    current_appendix = None
                continue
            parsed = parse_section_heading(block.text)
            if parsed:
                current_appendix = None
                section_ref, title = parsed
                current_section = {
                    "section_ref": section_ref,
                    "title": title,
                    "intro": [],
                    "subsections": [],
                }
                axis_sections.append(current_section)
                current_subsection = None
                continue
        if block.kind == "heading" and block.level == 3 and current_section is not None:
            parsed = parse_section_heading(block.text)
            if parsed:
                subsection_ref, title = parsed
                current_subsection = {
                    "subsection_ref": subsection_ref,
                    "title": title,
                    "intro": [],
                    "techniques": [],
                }
                current_section["subsections"].append(current_subsection)
            continue

        if current_appendix is not None:
            if block.kind == "table":
                appendices[current_appendix].extend(block.rows)
            elif block.kind == "paragraph":
                appendices[current_appendix].append(block.text)
            continue

        if current_subsection is not None:
            if block.kind == "paragraph":
                current_subsection["intro"].append(block.text)
            elif block.kind == "table":
                for row in block.rows:
                    name = row.get("Subtype") or row.get("Technique") or row.get("Name")
                    if not name:
                        first_key = next(iter(row.keys()), "")
                        name = row.get(first_key, "")
                    current_subsection["techniques"].append({"name": name, "fields": row})
            continue

        if current_section is not None and block.kind == "paragraph":
            current_section["intro"].append(block.text)

    return axis_sections, appendices


def infer_category_slug(path: Path) -> str | None:
    parent_name = path.parent.name
    if re.match(r"^\d{2}-", parent_name):
        return parent_name
    grandparent_name = path.parent.parent.name if path.parent.parent else ""
    if re.match(r"^\d{2}-", grandparent_name):
        return grandparent_name
    return None


def parse_topic_markdown(markdown: str, source_path: str) -> dict[str, object]:
    path = Path(source_path)
    blocks = parse_blocks(markdown)
    title = next((block.text for block in blocks if block.kind == "heading" and block.level == 1), path.stem)
    overview = extract_overview(blocks)
    axis1_sections, appendices = extract_axis1_and_appendices(blocks)
    return {
        "schema_version": "1.0.0",
        "source_path": str(path),
        "topic": {
            "title": title,
            "slug": slugify(path.stem),
            "category_slug": infer_category_slug(path),
            "overview": overview,
            "axis1_sections": axis1_sections,
            "appendices": appendices,
        },
    }
