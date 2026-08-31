"""Docs-citation drift check — the role docs are the ontology's spec.

If a docs/roles/*.md citation (`file.py:start-end`) no longer resolves to
the code it claims — file gone, range past EOF, or the named symbol no
longer in the cited lines — the docs have drifted from the code. Because
the docs are the source of truth we audit against, that drift is a
correctness bug, not a docs housekeeping issue. This check turns the
matrix RED on it.

Checks, per citation found in docs/roles/*.md:
  1. RESOLVE: the file exists (searched in agents/, agents/tools/,
     agents/verify/, and the repo root — the file names the docs cite are
     bare, e.g. `router.py` / `analyst_tools.py`).
  2. RANGE: start >= 1 and end <= total_lines (a citation past EOF means
     the code moved / was removed).
  3. SYMBOL (when the doc names one): the nearest backticked code token
     before the citation on its line (e.g. `RULE_MAP`, `def classify`,
     `ESCALATE_CATEGORIES`) must still appear in the cited range. If the
     doc cites a symbol and the lines no longer contain it, the citation
     is stale.

A citation with no adjacent symbol still gets checks 1+2 (catches file
deletion and gross line drift). The repo root is resolved from
SSOP_REPO_DIR, else walked up from this file; if docs/roles isn't present
at the resolved root, the check reports SKIP (docs not deployed there).

Usage: python3 -m verify.check_docs
Returns exit 0 (all resolve) or 1 (any problem).
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path
from typing import Any

# A citation: router.py:184-225  (end optional)
_CITE_RE = re.compile(r"(?<![A-Za-z0-9])([a-z_][a-z0-9_]*\.py):(\d+)(?:-(\d+))?")

# A code token the doc names near the citation (backtick-delimited).
_TOKEN_RE = re.compile(r"`([^`]+)`")

# Words that are prose, not symbols — strip from a token before matching.
_SKIP_WORDS = {"def", "class", "the", "a", "an", "and", "or", "on", "of", "in", "to", "for"}


def _resolve_root() -> Path:
    """Repo root: SSOP_REPO_DIR, else the nearest ancestor containing docs/roles.

    Handles both layouts:
      - repo:      <root>/agents/verify/check_docs.py, <root>/docs/roles/
      - runtime:   <root>/verify/check_docs.py,        <root>/docs/roles/
    The docs dir is the anchor — it's what the check reads and it exists in
    both deployments.
    """
    env = os.getenv("SSOP_REPO_DIR", "").strip()
    if env:
        return Path(env).resolve()
    d = Path(__file__).resolve().parent
    for cand in (d, *d.parents):
        if (cand / "docs" / "roles").is_dir():
            return cand
    return d.parent.parent.parent


def _find_file(root: Path, name: str) -> Path | None:
    """Resolve a bare `file.py` citation against either layout.

    Search order covers both the repo (<root>/agents/[tools|verify|]) and
    the runtime deploy (<root>/tools/, <root>/verify/, <root>/).
    """
    for sub in ("agents/tools", "agents/verify", "agents", "tools", "verify", ""):
        p = root / sub / name
        if p.exists():
            return p
    return None


def _symbol_near(text: str, cite_start: int) -> str | None:
    """Nearest backticked code token before the citation on the same line.

    Takes the first word of the token, strips punctuation/braces, and drops
    prose words. Returns None when the doc doesn't name a symbol there.
    """
    line = text[text.rfind("\n", 0, cite_start) + 1:cite_start]
    tokens = _TOKEN_RE.findall(line)
    if not tokens:
        return None
    for tok in reversed(tokens):
        first = tok.strip().split()[0] if tok.strip() else ""
        first = first.strip("`").strip("{}()[],:=").strip()
        if not first or first in _SKIP_WORDS or len(first) < 2:
            continue
        if "." in first:  # attribute path: settings.noise_rules -> last segment
            first = first.split(".")[-1]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", first):
            return first
    return None


def check_docs(root: Path | None = None) -> list[dict[str, Any]]:
    """Run the drift check over docs/roles/*.md. Returns problem dicts.

    Each problem: {cite, file, detail, kind: resolve|range|symbol}.
    Empty list = all citations resolve.
    """
    root = (root or _resolve_root()).resolve()
    docs_dir = root / "docs" / "roles"
    problems: list[dict[str, Any]] = []
    if not docs_dir.exists():
        return [{"kind": "skip", "detail": f"docs/roles not found at {docs_dir}"}]
    for md in sorted(docs_dir.glob("*.md")):
        text = md.read_text(encoding="utf-8")
        for m in _CITE_RE.finditer(text):
            fname, s_str, e_str = m.group(1), m.group(2), m.group(3)
            start, end = int(s_str), int(e_str) if e_str else int(s_str)
            fpath = _find_file(root, fname)
            if fpath is None:
                problems.append({"kind": "resolve", "cite": m.group(0),
                                 "file": fname, "detail": "file not found in agents//agents/tools//agents/verify/root"})
                continue
            lines = fpath.read_text(encoding="utf-8").splitlines()
            total = len(lines)
            if start < 1 or end > total or start > total:
                problems.append({"kind": "range", "cite": m.group(0), "file": str(fpath),
                                 "detail": f"range {start}-{end} outside file ({total} lines)"})
                continue
            sym = _symbol_near(text, m.start())
            if sym:
                window = "\n".join(lines[start - 1:end])
                if not re.search(rf"\b{re.escape(sym)}\b", window):
                    # A one-line citation that RETURNS/assigns a constant is a
                    # citation to the policy decision, not to the constant's
                    # literal value — the doc often names the VALUE (e.g.
                    # "Default -> (operational, None)" cites the line
                    # `return DEFAULT_CATEGORY, DEFAULT_ROLE`). Accept when the
                    # window is a return/assignment of ALL-CAPS constant(s).
                    ws = window.strip()
                    if start == end and (ws.startswith("return ") or " = " in ws):
                        consts = re.findall(r"\b[A-Z][A-Z0-9_]{2,}\b", ws)
                        if consts:
                            continue  # citation points at a policy-decision line
                    problems.append({"kind": "symbol", "cite": m.group(0),
                                     "file": str(fpath),
                                     "detail": f"symbol {sym!r} not in cited lines {start}-{end}"})
    return problems


def main() -> int:
    probs = check_docs()
    if not probs:
        print("docs citations: all resolve")
        return 0
    if any(p["kind"] == "skip" for p in probs):
        print("docs citations: SKIP — " + probs[0]["detail"])
        return 0
    print(f"docs citations: {len(probs)} problem(s)")
    for p in probs:
        print(f"  [{p['kind']}] {p['cite']} ({p['file']}): {p['detail']}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
