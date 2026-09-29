"""Scan many websites for AI-assistant links that carry hidden prompts.

For each site: check robots.txt, fetch the homepage, pick a few article pages
linked from it, and run promptlink over
  - every AI-assistant link found (links, buttons, URLs inside scripts), and
  - the page content itself: hidden text, comments, alt text, meta tags and
    structured data that speak to an AI and give it orders.
It also reads /llms.txt, a file some sites publish for AI to read.
Nothing is clicked, submitted or executed; pages are read the way a search
engine reads them.

    python research/scan.py --tranco top-1m.csv --sites 200 --out results.jsonl
    python research/scan.py --urls sites.txt --out results.jsonl

Politeness: one request at a time per site, a pause between pages of the
same site, robots.txt respected, a clear User-Agent with a contact URL,
short timeouts and a size cap.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import json
import os
import re
import sys
import threading
import time
import zlib
from concurrent.futures import ThreadPoolExecutor, as_completed
from html import unescape
from urllib import robotparser
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin, urlsplit
from urllib.request import Request, build_opener, HTTPRedirectHandler

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from promptlink import __version__  # noqa: E402
from promptlink.detector import scan_html, ASSISTANT_HOSTS, PATH_ASSISTANTS  # noqa: E402
from promptlink.page import candidate_chunks, extract_chunks, scan_chunks, scan_text_file  # noqa: E402

USER_AGENT = ("promptlink-research/%s (+https://github.com/Wido777/promptlink; "
              "reads public pages to measure AI memory-poisoning links)" % __version__)
TIMEOUT = 12
MAX_BYTES = 3_000_000
PAGE_PAUSE = 1.0
CANDIDATES_PER_PAGE = 8

# Cheap pre-filter: only run the full scan on pages that mention an assistant.
ASSISTANT_MARKERS = tuple(sorted({h for h in ASSISTANT_HOSTS} | {h for h, *_ in PATH_ASSISTANTS}))
ARTICLE_HINT = re.compile(r"/(?:blog|news|article|articles|post|posts|stories|story|insights|guides?|learn|resources)/|/20\d\d/|[a-z0-9]+-[a-z0-9]+-[a-z0-9]+", re.I)
SKIP_EXT = re.compile(r"\.(?:jpe?g|png|gif|webp|svg|ico|pdf|zip|gz|mp4|mp3|css|js|json|xml|rss|woff2?|ttf)(?:$|\?)", re.I)
HREF = re.compile(r"""href\s*=\s*["']([^"'#]+)""", re.I)


class _NoRedirectOffsite(HTTPRedirectHandler):
    """Follow redirects (http->https, www) but give up after a few hops."""
    max_redirections = 5


_opener = build_opener(_NoRedirectOffsite)


def fetch(url: str, want: str = "html") -> tuple[int, str, str]:
    """Return (status, final_url, text). Text is empty for the wrong content type or errors."""
    accept = "text/html,application/xhtml+xml" if want == "html" else "text/plain,text/markdown"
    req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": accept,
                                "Accept-Encoding": "gzip, deflate", "Accept-Language": "en;q=0.9,*;q=0.5"})
    try:
        with _opener.open(req, timeout=TIMEOUT) as r:
            ctype = r.headers.get("Content-Type", "")
            if want == "html" and "html" not in ctype.lower():
                return r.status, r.geturl(), ""
            if want == "text" and not any(t in ctype.lower() for t in ("text/plain", "markdown")):
                return r.status, r.geturl(), ""
            raw = r.read(MAX_BYTES + 1)[:MAX_BYTES]
            enc = (r.headers.get("Content-Encoding") or "").lower()
            if enc == "gzip":
                raw = gzip.decompress(raw) if raw[:2] == b"\x1f\x8b" else raw
            elif enc == "deflate":
                try:
                    raw = zlib.decompress(raw)
                except zlib.error:
                    raw = zlib.decompress(raw, -zlib.MAX_WBITS)
            charset = r.headers.get_content_charset() or "utf-8"
            return r.status, r.geturl(), raw.decode(charset, errors="replace")
    except HTTPError as e:
        return e.code, url, ""
    except (URLError, TimeoutError, OSError, ValueError, zlib.error, EOFError):
        return 0, url, ""


def robots_for(base: str) -> robotparser.RobotFileParser | None:
    rp = robotparser.RobotFileParser()
    req =Request(urljoin(base, "/robots.txt"), headers={"User-Agent": USER_AGENT})
    try:
        with _opener.open(req, timeout=TIMEOUT) as r:
            rp.parse(r.read(500_000).decode("utf-8", errors="replace").splitlines())
            return rp
    except HTTPError as e:
        if e.code in (401, 403):
            rp.disallow_all = True      # the standard treats these as "keep out"
            return rp
        rp.allow_all = True             # 404 and friends: no rules
        return rp
    except (URLError, TimeoutError, OSError, ValueError):
        return None                     # unreachable: skip the site


def prepare(html: str) -> str:
    """Undo the escaping that hides URLs inside inline JSON and scripts."""
    return (html.replace("\\/", "/").replace("\\u0026", "&").replace("\\u003d", "=")
                .replace("\\u003f", "?").replace("\\u0025", "%"))


def mentions_assistant(html: str) -> bool:
    low = html.lower()
    return any(m in low for m in ASSISTANT_MARKERS)


def article_links(base_url: str, html: str, limit: int) -> list[str]:
    host = urlsplit(base_url).hostname or ""
    bare = host[4:] if host.startswith("www.") else host
    seen, scored = set(), []
    for href in HREF.findall(html):
        u = urljoin(base_url, unescape(href.strip()))
        p = urlsplit(u)
        h = (p.hostname or "")
        if p.scheme not in ("http", "https") or (h != host and h.removeprefix("www.") != bare):
            continue
        if SKIP_EXT.search(p.path) or p.path in ("", "/"):
            continue
        clean = p._replace(query="", fragment="").geturl()
        if clean in seen:
            continue
        seen.add(clean)
        score = (2 if ARTICLE_HINT.search(p.path) else 0) + min(p.path.count("-"), 6) / 3
        scored.append((score, clean))
    scored.sort(key=lambda s: -s[0])
    return [u for s, u in scored[:limit] if s > 0]


def summarise_report(rep) -> dict:
    return {"assistant": rep.assistant, "param": rep.param, "verdict": rep.verdict, "score": rep.score,
            "rules": [f.rule for f in rep.findings], "prompt": (rep.prompt or "")[:1500],
            "wrapped": len(rep.unwrapped_from)}


def summarise_content(rep) -> dict:
    return {"verdict": rep.verdict, "chunks": rep.chunks, "hidden_chunks": rep.hidden_chunks,
            "findings": [{"verdict": f.verdict, "where": f.where, "how": f.how, "tag": f.tag,
                          "rules": [x.rule for x in f.findings], "text": f.text[:600]}
                         for f in rep.findings[:20]]}


def scan_page(url: str, html: str) -> dict:
    page = {"url": url, "ai_links": []}
    if not html:
        return page
    chunks = extract_chunks(html)
    page["content"] = summarise_content(scan_chunks(chunks))
    # Texts worth an AI review later (hidden text about AI, orders, memory...).
    page["candidates"] = [{"where": c.where, "how": c.how, "tag": c.tag, "text": c.text[:600]}
                          for c in candidate_chunks(chunks, limit=CANDIDATES_PER_PAGE)]
    if not mentions_assistant(html):
        return page
    seen = set()
    for rep in scan_html(prepare(html)):
        key = (rep.assistant, rep.prompt)
        if key in seen:
            continue
        seen.add(key)
        page["ai_links"].append(summarise_report(rep))
    return page


def scan_site(domain: str, pages_per_site: int) -> dict:
    started = time.time()
    site = {"site": domain, "status": "ok", "pages": [], "robots": "allowed"}
    base = None
    candidates = [domain.rstrip("/") + "/"] if "://" in domain else [f"https://{domain}/", f"https://www.{domain}/"]
    for candidate in candidates:
        rp = robots_for(candidate)
        if rp is not None:
            base = candidate
            break
    if base is None:
        site["status"] = "unreachable"
        return site
    if not rp.can_fetch(USER_AGENT, base):
        site["status"], site["robots"] = "robots_disallowed", "disallowed"
        return site
    status, final, html = fetch(base)
    if status == 0 or not html:
        site["status"] = f"no_html:{status}"
        return site
    site["pages"].append(scan_page(final, html))
    llms = urljoin(final, "/llms.txt")
    if rp.can_fetch(USER_AGENT, llms):
        time.sleep(PAGE_PAUSE)
        s, _, text = fetch(llms, want="text")
        if s == 200 and text.strip() and not text.lstrip().startswith("<"):
            site["llms_txt"] = summarise_content(scan_text_file(text))
    for url in article_links(final, html, pages_per_site):
        if not rp.can_fetch(USER_AGENT, url):
            continue
        time.sleep(PAGE_PAUSE)
        s, f, h = fetch(url)
        if s and h:
            site["pages"].append(scan_page(f, h))
    site["seconds"] = round(time.time() - started, 1)
    return site


def load_sites(args) -> list[str]:
    if args.urls:
        with open(args.urls, encoding="utf-8") as fh:
            sites = [l.strip() for l in fh if l.strip() and not l.startswith("#")]
    else:
        with open(args.tranco, encoding="utf-8") as fh:
            sites = [row[1].strip() for row in csv.reader(fh) if len(row) >= 2]
    if args.random:
        import random
        pool = sites[: args.random_from] if args.random_from else sites
        return random.Random(args.seed).sample(pool, min(args.sites, len(pool)))
    return sites[args.offset: args.offset + args.sites]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    src = ap.add_mutually_exclusive_group(required=True)
    src.add_argument("--tranco", help="Tranco CSV (rank,domain)")
    src.add_argument("--urls", help="text file with one domain (or host:port) per line")
    ap.add_argument("--sites", type=int, default=200)
    ap.add_argument("--offset", type=int, default=0)
    ap.add_argument("--random", action="store_true", help="draw a random sample instead of the top ranks")
    ap.add_argument("--random-from", type=int, default=0, help="sample only from the top N ranks (0 = whole list)")
    ap.add_argument("--seed", type=int, default=1, help="random seed, so a sample can be repeated")
    ap.add_argument("--pages-per-site", type=int, default=2)
    ap.add_argument("--workers", type=int, default=24, help="sites scanned in parallel (one request at a time per site)")
    ap.add_argument("--out", required=True)
    args = ap.parse_args(argv)

    sites = load_sites(args)
    lock, done = threading.Lock(), 0
    with open(args.out, "w", encoding="utf-8") as out, ThreadPoolExecutor(args.workers) as pool:
        futures = {pool.submit(scan_site, s, args.pages_per_site): s for s in sites}
        for fut in as_completed(futures):
            try:
                result = fut.result()
            except Exception as e:  # one broken site must never stop the scan
                result = {"site": futures[fut], "status": f"error:{type(e).__name__}", "pages": []}
            with lock:
                out.write(json.dumps(result, ensure_ascii=False) + "\n")
                out.flush()
                done += 1
                if done % 25 == 0 or done == len(sites):
                    print(f"{done}/{len(sites)} sites", file=sys.stderr, flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
