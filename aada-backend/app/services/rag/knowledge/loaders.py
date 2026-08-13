"""
Knowledge-source loaders.

Each loader reads one source format and emits `KnowledgeDocument`s with:
  - a stable `doc_id` (so re-ingesting updates rather than duplicates),
  - a `chunk_strategy` that fits the source (atomic items → STRUCTURED;
    long prose → MARKDOWN), and
  - searchable, self-contained `text` (we fold the key fields into the body so a
    retrieved chunk carries its own context, e.g. an ATT&CK technique's detection
    and mitigation travel with it).
"""
from __future__ import annotations

import json
from pathlib import Path

from app.logging_config import get_logger
from app.services.rag.schemas import ChunkStrategy, KnowledgeDocument, SourceType

logger = get_logger(__name__)

# repo-root/data/knowledge  (…/app/services/rag/knowledge/loaders.py → up 4)
DEFAULT_DATA_DIR = Path(__file__).resolve().parents[4] / "data" / "knowledge"


# ── MITRE ATT&CK ──────────────────────────────────────────────────────────────
def load_mitre(data_dir: Path) -> list[KnowledgeDocument]:
    path = data_dir / "mitre_attack.json"
    if not path.exists():
        return []
    docs = []
    for t in json.loads(path.read_text()):
        text = (
            f"MITRE ATT&CK {t['id']} — {t['name']} (Tactic: {t['tactic']})\n\n"
            f"Description: {t['description']}\n\n"
            f"Detection: {t.get('detection', '')}\n\n"
            f"Mitigation: {t.get('mitigation', '')}"
        )
        docs.append(KnowledgeDocument(
            doc_id=f"mitre:{t['id']}",
            source_type=SourceType.MITRE_ATTACK,
            title=f"{t['id']} {t['name']}",
            text=text,
            chunk_strategy=ChunkStrategy.STRUCTURED,
            metadata={
                "reference": t["id"], "technique": t["id"], "name": t["name"],
                "tactic": t["tactic"], "tactic_id": t.get("tactic_id", ""),
            },
        ))
    return docs


# ── OWASP Top 10 ──────────────────────────────────────────────────────────────
def load_owasp(data_dir: Path) -> list[KnowledgeDocument]:
    path = data_dir / "owasp_top10.json"
    if not path.exists():
        return []
    docs = []
    for o in json.loads(path.read_text()):
        text = (
            f"OWASP {o['id']} — {o['name']}\n\n"
            f"Description: {o['description']}\n\n"
            f"Example: {o.get('example', '')}\n\n"
            f"Prevention: {o.get('prevention', '')}"
        )
        docs.append(KnowledgeDocument(
            doc_id=f"owasp:{o['id']}",
            source_type=SourceType.OWASP_TOP10,
            title=f"{o['id']} {o['name']}",
            text=text,
            chunk_strategy=ChunkStrategy.STRUCTURED,
            metadata={"reference": o["id"], "name": o["name"]},
        ))
    return docs


# ── Sigma rules (YAML) ────────────────────────────────────────────────────────
def load_sigma(data_dir: Path) -> list[KnowledgeDocument]:
    folder = data_dir / "sigma_rules"
    if not folder.exists():
        return []
    try:
        import yaml  # lazy; PyYAML
    except ImportError:
        logger.warning("pyyaml_missing_skipping_sigma")
        return []

    docs = []
    for path in sorted(folder.glob("*.yml")) + sorted(folder.glob("*.yaml")):
        rule = yaml.safe_load(path.read_text())
        if not rule:
            continue
        tags = rule.get("tags", []) or []
        text = (
            f"Sigma Rule: {rule.get('title', path.stem)}\n\n"
            f"Description: {rule.get('description', '')}\n\n"
            f"Log source: {json.dumps(rule.get('logsource', {}))}\n"
            f"Detection: {json.dumps(rule.get('detection', {}))}\n"
            f"Level: {rule.get('level', 'medium')}\n"
            f"False positives: {', '.join(rule.get('falsepositives', []) or [])}\n"
            f"ATT&CK tags: {', '.join(tags)}"
        )
        docs.append(KnowledgeDocument(
            doc_id=f"sigma:{rule.get('id', path.stem)}",
            source_type=SourceType.SIGMA_RULE,
            title=rule.get("title", path.stem),
            text=text,
            chunk_strategy=ChunkStrategy.STRUCTURED,
            metadata={
                "reference": rule.get("title", path.stem),
                "level": rule.get("level", "medium"),
                "tags": tags,
            },
        ))
    return docs


# ── NIST documents (Markdown) ─────────────────────────────────────────────────
def load_nist(data_dir: Path) -> list[KnowledgeDocument]:
    return _load_markdown_dir(data_dir / "nist", SourceType.NIST, "nist")


# ── Incident-response guides (Markdown) ───────────────────────────────────────
def load_ir_guides(data_dir: Path) -> list[KnowledgeDocument]:
    return _load_markdown_dir(data_dir / "ir_guides", SourceType.IR_GUIDE, "ir")


def _load_markdown_dir(folder: Path, source: SourceType, prefix: str) -> list[KnowledgeDocument]:
    if not folder.exists():
        return []
    docs = []
    for path in sorted(folder.glob("*.md")):
        text = path.read_text()
        first_line = next((line for line in text.splitlines() if line.strip()), path.stem)
        title = first_line.lstrip("# ").strip()
        docs.append(KnowledgeDocument(
            doc_id=f"{prefix}:{path.stem}",
            source_type=source,
            title=title,
            text=text,
            chunk_strategy=ChunkStrategy.MARKDOWN,   # split long prose on headings
            metadata={"reference": path.stem, "filename": path.name},
        ))
    return docs


# ── Aggregate ─────────────────────────────────────────────────────────────────
def load_all(data_dir: Path | str | None = None) -> list[KnowledgeDocument]:
    base = Path(data_dir) if data_dir else DEFAULT_DATA_DIR
    docs: list[KnowledgeDocument] = []
    for loader in (load_mitre, load_owasp, load_sigma, load_nist, load_ir_guides):
        docs.extend(loader(base))
    logger.info("knowledge_loaded", data_dir=str(base), documents=len(docs))
    return docs
