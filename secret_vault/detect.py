"""Secret detection and placeholder substitution (pure functions, no Hermes imports)."""
from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass

PLACEHOLDER_RE = re.compile(r"\{\{SECRET:([A-Za-z0-9_.\-]{1,64})\}\}")
NAME_RE = re.compile(r"^[A-Za-z0-9_.\-]{1,64}$")

# (kind, pattern). Order matters: more specific first.
PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key", re.compile(
        r"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----[\s\S]+?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{22,255}\b")),
    ("github", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("openai", re.compile(r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{20,}\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("telegram_bot", re.compile(r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b")),
    ("google_api", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack", re.compile(r"\bxox[abposr]-[A-Za-z0-9\-]{10,}\b")),
]

# Candidate tokens for the entropy check: long runs of token-ish characters.
_GENERIC_RE = re.compile(r"(?<![A-Za-z0-9_\-+/=])[A-Za-z0-9_\-+/=]{24,}(?![A-Za-z0-9_\-+/=])")


def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _looks_generic_secret(tok: str, threshold: float) -> bool:
    if PLACEHOLDER_RE.search(tok):
        return False
    classes = sum(bool(re.search(p, tok)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]"))
    if classes < 2:          # plain words / hex-only hashes of one class are skipped
        return False
    if re.fullmatch(r"[A-Za-z]+(?:[_\-][A-Za-z]+)*", tok):  # snake/kebab identifiers
        return False
    if tok.startswith(("http", "www.")) or "/" in tok.strip("/") and tok.count("/") > 2:  # paths/urls
        return False
    return shannon_entropy(tok) >= threshold


@dataclass(frozen=True)
class Finding:
    kind: str
    value: str
    start: int
    end: int


def find_secrets(text: str, *, entropy_threshold: float = 4.0, generic: bool = True) -> list[Finding]:
    """Return non-overlapping findings, ordered by position."""
    if not isinstance(text, str) or not text:
        return []
    taken: list[tuple[int, int]] = []
    out: list[Finding] = []

    def free(a: int, b: int) -> bool:
        return all(b <= s or a >= e for s, e in taken)

    for kind, pat in PATTERNS:
        for m in pat.finditer(text):
            if free(m.start(), m.end()):
                taken.append((m.start(), m.end()))
                out.append(Finding(kind, m.group(0), m.start(), m.end()))
    if generic:
        for m in _GENERIC_RE.finditer(text):
            tok = m.group(0)
            if free(m.start(), m.end()) and _looks_generic_secret(tok, entropy_threshold):
                taken.append((m.start(), m.end()))
                out.append(Finding("generic", tok, m.start(), m.end()))
    out.sort(key=lambda f: f.start)
    return out


def auto_name(kind: str, value: str) -> str:
    """Deterministic name, so the same secret pasted twice maps to the same placeholder."""
    return f"{kind}_{hashlib.sha256(value.encode('utf-8')).hexdigest()[:8]}"


def placeholder(name: str) -> str:
    return "{{SECRET:%s}}" % name


def substitute(text: str, findings: list[Finding], names: list[str]) -> str:
    """Replace each finding with the placeholder for the matching name."""
    parts, last = [], 0
    for f, n in zip(findings, names):
        parts.append(text[last:f.start])
        parts.append(placeholder(n))
        last = f.end
    parts.append(text[last:])
    return "".join(parts)


def resolve(obj, lookup):
    """Recursively replace placeholders in str/list/dict with lookup(name); unknown names stay."""
    if isinstance(obj, str):
        def rep(m):
            v = lookup(m.group(1))
            return v if v is not None else m.group(0)
        return PLACEHOLDER_RE.sub(rep, obj)
    if isinstance(obj, list):
        return [resolve(x, lookup) for x in obj]
    if isinstance(obj, tuple):
        return tuple(resolve(x, lookup) for x in obj)
    if isinstance(obj, dict):
        return {k: resolve(v, lookup) for k, v in obj.items()}
    return obj


def contains_placeholder(obj) -> bool:
    if isinstance(obj, str):
        return bool(PLACEHOLDER_RE.search(obj))
    if isinstance(obj, (list, tuple)):
        return any(contains_placeholder(x) for x in obj)
    if isinstance(obj, dict):
        return any(contains_placeholder(v) for v in obj.values())
    return False


def redact(text: str, secrets: dict[str, str], *, min_len: int = 6) -> str:
    """Replace any known secret value in *text* with its placeholder (longest values first)."""
    if not isinstance(text, str) or not text or not secrets:
        return text
    for name, value in sorted(secrets.items(), key=lambda kv: -len(kv[1] or "")):
        if value and len(value) >= min_len and value in text:
            text = text.replace(value, placeholder(name))
    return text
