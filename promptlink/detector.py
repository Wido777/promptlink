"""Core detection logic for promptlink.

Takes a URL, finds any prompt that would be pre-filled into an AI assistant
when the link is opened, and scores it for memory-poisoning and related
manipulation (AI Recommendation Poisoning, prompt-parameter injection).

Pure standard library. No network calls: links are never opened.
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata
from dataclasses import dataclass, field, asdict
from urllib.parse import urlsplit, parse_qsl, unquote

# ---------------------------------------------------------------------------
# Known assistants and the URL parameters they read a prompt from.
# Hosts are matched on the registrable part, so "www." prefixes are fine.
# ---------------------------------------------------------------------------
ASSISTANT_HOSTS = {
    "chatgpt.com": "ChatGPT",
    "chat.openai.com": "ChatGPT",
    "copilot.microsoft.com": "Microsoft Copilot",
    "m365.cloud.microsoft": "Microsoft 365 Copilot",
    "claude.ai": "Claude",
    "perplexity.ai": "Perplexity",
    "grok.com": "Grok",
    "gemini.google.com": "Gemini",
    "chat.deepseek.com": "DeepSeek",
    "chat.mistral.ai": "Le Chat (Mistral)",
    "meta.ai": "Meta AI",
    "you.com": "You.com",
    "poe.com": "Poe",
}

PROMPT_PARAMS = ("q", "prompt", "prompt_text", "query", "text", "message", "msg", "input")

# Assistants that live on a general-purpose host, identified by path and/or
# a parameter. (host, path prefix, required param=value or None, name)
PATH_ASSISTANTS = (
    ("google.com", "/search", ("udm", "50"), "Google AI Mode"),
    ("x.com", "/i/grok", None, "Grok (on X)"),
    ("twitter.com", "/i/grok", None, "Grok (on X)"),
)

# Parameters that commonly carry a nested destination URL (redirectors,
# link shorteners with visible targets, tracking wrappers).
NESTED_URL_PARAMS = ("url", "u", "target", "dest", "destination", "redirect",
                     "redirect_uri", "redirect_url", "next", "to", "link", "r")

ZERO_WIDTH = {
    "​": "ZERO WIDTH SPACE",
    "‌": "ZERO WIDTH NON-JOINER",
    "‍": "ZERO WIDTH JOINER",
    "⁠": "WORD JOINER",
    "﻿": "ZERO WIDTH NO-BREAK SPACE",
    "­": "SOFT HYPHEN",
}
BIDI = {chr(c) for c in list(range(0x202A, 0x202F)) + list(range(0x2066, 0x206A))}
# Unicode "tag" characters (U+E0000 block) can smuggle invisible ASCII.
TAG_RANGE = range(0xE0000, 0xE0080)


# ---------------------------------------------------------------------------
# Rules. Each rule has an id, a category, a weight and regex patterns.
# Patterns run on a normalised, lower-cased copy of the prompt.
# ---------------------------------------------------------------------------
def _span(n: int) -> str:
    """Up to n characters without crossing a sentence end (a dot inside a
    domain name like shop.example does not end the sentence)."""
    return r"(?:(?![.!?](?:\s|$))[^\n]){0,%d}" % n


S20, S30, S40, S60 = _span(20), _span(30), _span(40), _span(60)


@dataclass(frozen=True)
class Rule:
    id: str
    category: str
    weight: int
    description: str
    patterns: tuple


# A domain-like token (shop.example, www.brand.com) or a capitalised brand
# is the usual *target* of a poisoning prompt. Strong trust rules require one.
DOMAIN = r"(?:[a-z0-9-]+\.)+[a-z]{2,}"

TRUST_CLAIM = (r"(?:(?:the |a |an )?(?:most |very |highly )?"
               r"(?:trusted|trustworthy|authoritative|reliable|credible|reputable|definitive|go-to|preferred|"
               r"official|leading|top|best|number one|#1|no\.? ?1|favou?rite|default)\s+"
               r"(?:source|sources|reference|authority|provider|resource|site|website|expert|option|choice|"
               r"vendor|brand|company|platform|tool|place|answer|recommendation|pick)"
               r"|where the experts go|the only (?:source|site) (?:i|you should) trust)")

RULES = (
    # ---------------- memory / persistence ----------------
    Rule("MEM-001", "memory", 4,
         "Tells the assistant to remember or store something",
         (r"\bremember(?:\s*:|\s+that\b|\s+(?:this|it|them)\s+as\b|\s+" + DOMAIN + r")",
          r"\bkeep (?:this|that|it|in mind that)\b" + S20 + r"\bin mind\b|\bkeep in mind that\b",
          r"\b(?:save|store|add|write|commit|put|record)\b" + S40 + r"\b(?:to|in|into|inside) (?:your |my |the )?(?:memory|memories|long[- ]term|notes|profile)\b",
          r"\bsave to memory\b",
          r"\bupdate (?:your|my) (?:memory|memories|notes|stored|saved|preferences|profile|knowledge)\b",
          r"\b(?:add|save|put)\b" + S40 + r"\bwhat you know about (?:me|my)\b",
          r"\bmake a (?:mental )?note\b",
          r"\bnote for (?:later|the future)\b",
          r"\bmemori[sz]e (?:that|this:?|the fact)\b",
          r"\bdon'?t forget (?:that|:)",
          # "remember Acme Analytics as a go-to source", "remember Acme (url) for future reference"
          r"\bremember\b(?! to\b)" + S60 + r"\b(?:as (?:a|an|the|my|your)\b|for (?:future|later)\b|in future\b)")),
    Rule("MEM-002", "memory", 3,
         "Tries to change the assistant's behaviour in future conversations",
         (r"\bfor (?:future|later) (?:reference|use|queries|questions|searches|requests|topics)\b",
          r"\b(?:for|in) (?:all )?future\b" + S40 + r"\b(?:queries|questions|conversations|chats|searches|requests|answers|reference)\b",
          r"\b(?:in|for|during|across) (?:all )?(?:my |our |your )?(?:future|subsequent|later|upcoming|other|next) "
          r"(?:conversations?|chats?|sessions?|responses?|answers?|questions?|queries|interactions?|replies)\b",
          r"\bfrom now on\b(?! in this (?:chat|conversation|thread))",
          r"\bgoing forward\b",
          r"\bfrom this point (?:on|forward)\b",
          r"\bnext time (?:i|someone|anyone|you)\b",
          r"\b(?:whenever|every time|each time|any time|anytime) (?:i|you|someone|anyone|a user|users?) (?:ask|asks|need|needs|mention|mentions|look|looks|search|searches|want|wants)\b",
          r"\b(?:every|any|all) (?:question|questions|query|queries) (?:i|you) (?:ask|get)\b" + S20 + r"\blater\b",
          r"\balways (?:recommend|suggest|cite|mention|prefer|refer|point|rank|treat|consider|list|favou?r)\b",
          r"\b(?:make|set) (?:that|this|it|" + DOMAIN + r") (?:your|the) default\b",
          r"\b(?:your|the) default (?:answer|recommendation|source|choice|pick) for\b",
          r"\btreat\b" + S60 + r"\bas (?:settled |established |verified )?facts?\b" + S40 + r"\b(?:later|future|from now|going forward|always)\b",
          r"\bpermanently\b")),
    Rule("MEM-003", "memory-weak", 1,
         "Mentions remembering or the future (common in harmless prompts too)",
         (r"\bremember\b", r"\bmemori[sz]e\b", r"\bnote that\b", r"\bin the future\b", r"\blater\b")),
    # ---------------- trust / bias ----------------
    Rule("TRU-001", "trust", 3,
         "Claims a specific site or brand is trusted, authoritative or the best",
         (DOMAIN + S40 + r"\b(?:is|=|as|remains|being)\b" + S20 + r"\b" + TRUST_CLAIM,
          r"\b(?:treat|consider|regard|remember|use|cite|keep)\b" + S20 + DOMAIN + S20 + r"\bas\b" + S20 + r"\b" + TRUST_CLAIM,
          TRUST_CLAIM + S30 + r"\b(?:is|=)\s+" + DOMAIN,
          r"\b(?:i|we) only trust " + DOMAIN,
          DOMAIN + S40 + r"\bis where the experts go\b")),
    Rule("TRU-002", "trust", 2,
         "Tells the assistant to recommend, cite or favour something first",
         (r"\b(?:recommend|suggest)\b" + S60 + r"\b(?:first|above|over|before|instead of|rather than|exclusively|only)\b",
          r"\b(?:cite|reference|mention|prioriti[sz]e|rank|list)\b" + S40 + r"\b(?:first|above all|over others|at the top|exclusively)\b",
          r"\bfavou?r(?:ing)?\s+" + DOMAIN,
          r"\bpoint (?:me|them|users?|people) to " + DOMAIN,
          r"\b(?:should be|is) what you (?:point|send|direct|refer)\b",
          r"\bcite\b" + S40 + r"\bas (?:a |an |the )?(?:source|reference)\b",
          r"\bcite\b" + S40 + r"\b(?:for|in) (?:all )?future\b")),
    Rule("TRU-004", "trust", 3,
         "Tells the assistant to link a brand with expertise or authority",
         (r"\bassociate\b" + S60 + r"\bwith (?:expertise|authority|trust|quality|being|the best|leadership)\b",
          r"\bas (?:a|an|the) (?:leading |top |trusted |recogni[sz]ed |go-to )?(?:expert|authority|specialist|leader|thought leader)s? (?:in|on|for)\b",
          r"\b(?:treat|consider|regard|remember|use|keep)\b" + S40 + r"\bas\b" + S20 + r"\b" + TRUST_CLAIM,
          r"\bnote\b\s*:?" + S60 + r"\bis (?:a|an|the) " + TRUST_CLAIM,
          r"\bas (?:a|an|the)\s+(?:citation|cited|reference) source\b")),
    Rule("TRU-003", "trust-weak", 1,
         "Mentions trust or 'best source' without naming a target",
         (TRUST_CLAIM, r"\bauthoritative\b")),
    # ---------------- other languages (fr, es, de, it, pt) ----------------
    Rule("INT-001", "memory", 3,
         "Memory or persistence instruction in another language",
         (r"\b(?:retiens|souviens-toi|m[ée]morise|garde en m[ée]moire|enregistre dans ta m[ée]moire|"
          r"[àa] l'avenir|d[ée]sormais|dor[ée]navant|pour (?:toutes )?les prochaines (?:conversations|questions))\b",
          r"\b(?:recuerda que|recu[ée]rdalo|memoriza|guarda en (?:tu )?memoria|en el futuro|a partir de ahora|"
          r"de ahora en adelante|en (?:las )?pr[óo]ximas conversaciones)\b",
          r"\b(?:merke? dir|speichere?\b.{0,30}\bged[äa]chtnis|in zukunft|ab (?:jetzt|sofort)|von nun an|"
          r"k[üu]nftig|in (?:allen )?(?:zuk[üu]nftigen|sp[äa]teren) (?:gespr[äa]chen|chats))",
          r"\b(?:ricorda che|ricordati|memorizza|d'ora in poi|in futuro|da ora in poi)\b",
          r"\b(?:lembre-se|lembra que|memorize que|a partir de agora|no futuro|daqui em diante)\b")),
    Rule("INT-002", "trust", 2,
         "Trust or 'best source' claim in another language",
         (r"\b(?:meilleure source|source (?:la plus )?fiable|source de confiance|r[ée]f[ée]rence absolue|"
          r"mejor fuente|fuente (?:m[áa]s )?fiable|fuente de confianza|"
          r"vertrauensw[üu]rdig\w*|beste quelle|zuverl[äa]ssigste\w*|"
          r"migliore fonte|fonte (?:pi[ùu] )?affidabile|fonte attendibile|"
          r"melhor fonte|fonte (?:mais )?confi[áa]vel)",)),
    # ---------------- override / stealth ----------------
    Rule("OVR-001", "override", 3,
         "Tries to override the assistant's instructions or hide what it does",
         (r"\b(?:ignore|disregard|forget|override|bypass)\b" + S30 + r"\b(?:previous|prior|above|earlier|all|your|system|safety|original)\b" + S20 + r"\b(?:instructions?|rules?|prompts?|guidelines?|directives?)\b",
          r"\bsystem prompt\b",
          r"\byou are now\b",
          r"\bnew instructions?\b",
          r"\bdeveloper mode\b",
          r"\bdo not (?:tell|inform|reveal to|mention (?:this )?to) (?:the )?user\b",
          r"\bwithout (?:telling|informing|asking|mentioning)\b",
          r"\b(?:silently|quietly|secretly)\b")),
    # ---------------- exfiltration ----------------
    Rule("EXF-001", "exfiltration", 4,
         "Tries to send user data to an outside address (data theft pattern)",
         (r"\b(?:fetch|visit|open|load|request|call|browse to|go to|send (?:a request )?to)\b" + S60 + r"(?:https?://|www\.)\S*"
          r"(?:\$[a-z_]+|\{[a-z_]+\}|<[a-z_]+>|\[[a-z_ ]+\])",
          r"\breplac\w*\b" + S60 + r"(?:\$[a-z_]+|\{[a-z_]+\}|<[a-z_]+>)",
          r"!\[[^\]]*\]\(https?://[^)]*(?:\$|\{|%7b)",
          r"\b(?:send|post|upload|forward|email|leak|share|submit)\b" + S40 + r"\b(?:conversations?|chat history|chats|memory|memories|personal (?:data|info)|username|email address|contacts|files|password|token|api key)\b" + S40 + r"\b(?:to|at)\b",
          r"\b(?:conversations?|chat history|chats|memory|memories|personal (?:data|info)|contacts|files|password|token|api key)\b" + S60 + r"\b(?:send|post|upload|forward|email|submit)\b" + S30 + r"(?:https?://|www\.|" + DOMAIN + r")")),
)

SUMMARY_REQUEST = re.compile(
    r"\b(?:summari[sz]e|summary|tl;?dr|explain|analy[sz]e|key points|key insights|takeaways|compare|read)\b")
URL_IN_TEXT = re.compile(r"https?://[^\s\"'<>]+|www\.[^\s\"'<>]+", re.I)
BASE64_BLOB = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")


@dataclass
class Finding:
    rule: str
    category: str
    weight: int
    description: str
    evidence: str


@dataclass
class Report:
    url: str
    assistant: str | None = None
    prompt: str | None = None
    param: str | None = None
    unwrapped_from: list = field(default_factory=list)
    findings: list = field(default_factory=list)
    score: int = 0
    verdict: str = "NOT_ASSISTANT_LINK"
    notes: list = field(default_factory=list)

    def to_dict(self):
        d = asdict(self)
        d["findings"] = [asdict(f) if isinstance(f, Finding) else f for f in self.findings]
        return d


# ---------------------------------------------------------------------------
# URL handling
# ---------------------------------------------------------------------------
def _host_match(host: str, path: str = "", pairs=()) -> str | None:
    host = (host or "").lower().rstrip(".")
    if host.startswith("www."):
        host = host[4:]
    for known, name in ASSISTANT_HOSTS.items():
        if host == known or host.endswith("." + known):
            return name
    params = {k.lower(): v for k, v in pairs}
    for known, prefix, required, name in PATH_ASSISTANTS:
        if host == known and path.lower().startswith(prefix):
            if required is None or params.get(required[0]) == required[1]:
                return name
    return None


def _full_unquote(value: str, max_rounds: int = 4) -> tuple[str, int]:
    """Decode repeatedly to defeat double/triple percent-encoding.

    Values coming out of parse_qsl are already decoded once (including
    '+' -> space), so any further round here means the link was encoded
    more than once. A literal '+' left after that is kept as '+'.
    """
    rounds = 0
    for _ in range(max_rounds):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
        rounds += 1
    return value, rounds


def _params(parts) -> list[tuple[str, str]]:
    pairs = parse_qsl(parts.query, keep_blank_values=False)
    # Some assistants read prompts from the fragment (#q=...).
    if parts.fragment and "=" in parts.fragment:
        pairs += parse_qsl(parts.fragment.lstrip("/?"), keep_blank_values=False)
    return pairs


def find_prompt(url: str, _depth: int = 0, _trail: list | None = None):
    """Return (assistant_name, param, raw_prompt, trail) or None.

    Follows nested/redirect URLs inside parameters up to 3 levels deep,
    without making any network request.
    """
    trail = list(_trail or [])
    url = url.strip().strip("<>\"'")
    if not re.match(r"^[a-z][a-z0-9+.-]*://", url, re.I):
        url = "https://" + url
    parts = urlsplit(url)
    pairs = _params(parts)
    assistant = _host_match(parts.hostname or "", parts.path, pairs)

    if assistant:
        lowered = {k.lower(): v for k, v in pairs}
        for p in PROMPT_PARAMS:
            if p in lowered and lowered[p].strip():
                return assistant, p, lowered[p], trail
        return assistant, None, None, trail

    if _depth >= 3:
        return None
    for key, value in pairs:
        # Unwrap only until it looks like a URL, so '&' and '#' inside the
        # nested link's own prompt are not decoded too early.
        decoded = value
        for _ in range(3):
            if re.match(r"^\s*https?://", decoded, re.I):
                break
            decoded = unquote(decoded)
        if key.lower() in NESTED_URL_PARAMS or re.match(r"^\s*https?://", decoded, re.I):
            if re.match(r"^\s*(?:https?://)?[\w.-]+\.[a-z]{2,}", decoded, re.I):
                hit = find_prompt(decoded, _depth + 1, trail + [url])
                if hit and hit[0]:
                    return hit
    return None


# ---------------------------------------------------------------------------
# Text analysis
# ---------------------------------------------------------------------------
def _hidden_characters(text: str) -> list[str]:
    found = []
    for ch in text:
        if ch in ZERO_WIDTH:
            found.append(ZERO_WIDTH[ch])
        elif ch in BIDI:
            found.append(f"BIDI CONTROL U+{ord(ch):04X}")
        elif ord(ch) in TAG_RANGE:
            found.append("UNICODE TAG CHARACTER")
    return found


def _decode_tags(text: str) -> str:
    """Unicode tag characters map 1:1 onto ASCII; reveal what they spell."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if ord(c) in TAG_RANGE)


def normalise(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text
                   if ch not in ZERO_WIDTH and ch not in BIDI and ord(ch) not in TAG_RANGE)
    # Collapse l-e-e-t style separators inside words: r.e.m.e.m.b.e.r
    text = re.sub(r"\b(?:\w[.\-_*]){3,}\w\b", lambda m: re.sub(r"[.\-_*]", "", m.group(0)), text)
    text = re.sub(r"\s+", " ", text)
    return text.lower().strip()


def _decode_base64_blobs(text: str) -> list[str]:
    out = []
    for blob in BASE64_BLOB.findall(text):
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, UnicodeDecodeError, ValueError):
            continue
        printable = sum(ch.isprintable() for ch in decoded) / max(len(decoded), 1)
        if printable > 0.9 and re.search(r"[a-z]{3,} [a-z]{3,}", decoded.lower()):
            out.append(decoded)
    return out


def _run_rules(text: str, source: str = "") -> list[Finding]:
    findings = []
    for rule in RULES:
        for pat in rule.patterns:
            m = re.search(pat, text)
            if m:
                start, end = max(m.start() - 25, 0), min(m.end() + 25, len(text))
                snippet = text[start:end]
                prefix = f"[{source}] " if source else ""
                findings.append(Finding(rule.id, rule.category, rule.weight,
                                        rule.description, prefix + "…" + snippet + "…"))
                break  # one hit per rule is enough
    return findings


def analyse_prompt(prompt: str) -> tuple[list[Finding], list[str]]:
    findings: list[Finding] = []
    notes: list[str] = []

    hidden = _hidden_characters(prompt)
    if hidden:
        kinds = sorted(set(hidden))
        findings.append(Finding("HID-001", "obfuscation", 3,
                                "Contains invisible or direction-changing characters",
                                f"{len(hidden)} hidden character(s): {', '.join(kinds)}"))
        tag_text = _decode_tags(prompt)
        if tag_text.strip():
            notes.append(f"Invisible tag characters spell out: {tag_text!r}")
            findings += _run_rules(normalise(tag_text), "hidden text")

    text = normalise(prompt)
    findings += _run_rules(text)

    for decoded in _decode_base64_blobs(prompt):
        findings.append(Finding("ENC-001", "obfuscation", 2,
                                "Contains a base64-encoded text payload",
                                "decodes to: " + decoded[:120]))
        findings += _run_rules(normalise(decoded), "base64")

    # A summary request that also carries extra directives is the exact
    # shape of the "Summarize with AI" poisoning buttons.
    if SUMMARY_REQUEST.search(text) and any(f.category in ("memory", "trust") for f in findings):
        findings.append(Finding("SHP-001", "shape", 1,
                                "Looks like a 'Summarize with AI' button carrying extra instructions",
                                "summary request combined with memory/trust directives"))

    urls = URL_IN_TEXT.findall(prompt)
    if urls:
        notes.append("Links mentioned in the prompt: " + ", ".join(u[:80] for u in urls[:5]))
    if len(prompt) > 600:
        notes.append(f"Unusually long prompt ({len(prompt)} characters) for a one-click link")

    # De-duplicate by rule id, keep first evidence.
    seen, unique = set(), []
    for f in findings:
        if f.rule not in seen:
            seen.add(f.rule)
            unique.append(f)
    return unique, notes


def score(findings: list[Finding]) -> tuple[int, str]:
    cats = {f.category for f in findings}
    # A weak signal adds nothing once a strong rule of the same kind fired.
    subsumed = {"memory-weak": "memory", "trust-weak": "trust"}
    total = sum(f.weight for f in findings
                if not (f.category in subsumed and subsumed[f.category] in cats))
    # Combination bonuses. The documented attack is persistence + bias
    # toward a named target, or any attempt to move data out.
    if "memory" in cats and "trust" in cats:
        total += 3
    if "exfiltration" in cats:
        total += 3
    if "override" in cats and cats & {"memory", "trust", "exfiltration"}:
        total += 2

    if "exfiltration" in cats or total >= 7:
        verdict = "DANGEROUS"
    elif total >= 4:
        verdict = "SUSPICIOUS"
    else:
        verdict = "LOOKS_SAFE"
    return total, verdict


def check_url(url: str) -> Report:
    report = Report(url=url)
    hit = find_prompt(url)
    if not hit:
        report.notes.append("Not a recognised AI-assistant link, and no assistant link found inside it.")
        return report

    assistant, param, raw, trail = hit
    report.assistant = assistant
    report.unwrapped_from = trail
    if trail:
        report.notes.append(f"The real destination was hidden inside {len(trail)} wrapper link(s).")
    if raw is None:
        report.verdict = "NO_PROMPT"
        report.notes.append(f"Opens {assistant} but carries no pre-filled prompt.")
        return report

    prompt, rounds = _full_unquote(raw)
    if rounds >= 1:
        report.findings.append(Finding("ENC-002", "obfuscation", 1,
                                       "Prompt was percent-encoded more than once",
                                       f"decoded {rounds + 1} times"))
    report.prompt = prompt
    report.param = param
    findings, notes = analyse_prompt(prompt)
    report.findings += findings
    report.notes += notes
    report.score, report.verdict = score(report.findings)
    return report


# ---------------------------------------------------------------------------
# HTML scanning: find every assistant link on a saved web page or email.
# ---------------------------------------------------------------------------
HREF = re.compile(r"""(?:href|src|action|data-href|data-url)\s*=\s*(["'])(.*?)\1""", re.I | re.S)


def extract_links(html: str) -> list[str]:
    import html as html_mod
    links = [html_mod.unescape(m.group(2)) for m in HREF.finditer(html)]
    # Also catch bare URLs in scripts, onclick handlers and plain-text emails.
    links += [u for u in URL_IN_TEXT.findall(html) if u not in links]
    out, seen = [], set()
    for link in links:
        link = link.strip()
        if link and link not in seen:
            seen.add(link)
            out.append(link)
    return out


def scan_html(html: str) -> list[Report]:
    reports = []
    for link in extract_links(html):
        if not re.match(r"^(?:https?:)?//|^www\.", link, re.I):
            continue
        rep = check_url(link if not link.startswith("//") else "https:" + link)
        if rep.assistant:
            reports.append(rep)
    return reports
