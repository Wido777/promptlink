// promptlink content script: reads the page you are on, as rendered, and
// looks for (1) text that speaks to an AI and gives it orders, noting whether
// you can see it, and (2) AI-assistant links with poisoned prompts.
// Runs entirely in the page; nothing is stored or sent anywhere.
(function () {
  "use strict";
  if (window.__promptlinkLoaded) return;
  window.__promptlinkLoaded = true;

  const api = globalThis.browser || globalThis.chrome;
  const PL = globalThis.promptlink;
  const PG = globalThis.promptlinkPage;

  const SKIP = new Set(["SCRIPT", "STYLE", "NOSCRIPT", "SVG", "MATH", "IFRAME", "OBJECT", "CANVAS",
                        "SELECT", "OPTION", "TEMPLATE", "HEAD", "TITLE"]);
  const SR = new Set(PG.srClasses);
  const META = new Set(PG.metaNames);
  const MAX = 4000;
  const FLAGGED = { SUSPICIOUS: 1, DANGEROUS: 2 };

  let last = null;          // most recent result, with DOM references for "show"

  // ---------------------------------------------------------- visibility
  function rgba(s) {
    const m = /rgba?\(([^)]+)\)/.exec(s || "");
    if (!m) return null;
    const p = m[1].split(/[\s,\/]+/).filter(Boolean).map(parseFloat);
    return { r: p[0], g: p[1], b: p[2], a: p.length > 3 ? p[3] : 1 };
  }

  function makeVisibility() {
    const cache = new Map();
    const bgCache = new Map();
    const docW = Math.max(document.documentElement.scrollWidth, window.innerWidth);

    function own(el) {
      const cs = getComputedStyle(el);
      if (el.hidden) return "hidden attribute";
      if (cs.display === "none") return "display:none";
      if (cs.visibility === "hidden" || cs.visibility === "collapse") return "visibility:hidden";
      if (parseFloat(cs.opacity) === 0) return "opacity:0";
      if (cs.contentVisibility === "hidden") return "content-visibility:hidden";
      for (const c of el.classList) if (SR.has(c.toLowerCase())) return "screen-reader-only class";
      if (/^rect\(0/.test(cs.clip) || /inset\((?:50|100)%/.test(cs.clipPath)) return "clipped away";
      if (/^matrix\(0, 0, 0, 0/.test(cs.transform)) return "scaled to zero";
      if (cs.position === "absolute" || cs.position === "fixed") {
        const r = el.getBoundingClientRect();
        const x = r.left + window.scrollX, y = r.top + window.scrollY;
        if (x + r.width <= 0 || y + r.height <= 0 || x >= docW + 500) return "moved off-screen";
      }
      if (cs.overflow === "hidden" || cs.overflowY === "hidden" || cs.overflowX === "hidden") {
        const r = el.getBoundingClientRect();
        if (r.width <= 1 || r.height <= 1) return "zero height";
      }
      if (/^-\d{3,}/.test(cs.textIndent)) return "moved off-screen";
      return "";
    }

    function reason(el) {
      if (!el || el.nodeType !== 1) return "";
      if (cache.has(el)) return cache.get(el);
      let r = own(el);
      if (!r) {
        const parent = el.parentElement || (el.getRootNode() && el.getRootNode().host);
        r = parent ? reason(parent) : "";
      }
      cache.set(el, r);
      return r;
    }

    function background(el) {
      if (!el || el.nodeType !== 1) return { r: 255, g: 255, b: 255, a: 1 };
      if (bgCache.has(el)) return bgCache.get(el);
      const cs = getComputedStyle(el);
      let out;
      if (cs.backgroundImage && cs.backgroundImage !== "none") out = null;   // can't judge images
      else {
        const c = rgba(cs.backgroundColor);
        out = c && c.a > 0.9 ? c : background(el.parentElement);
      }
      bgCache.set(el, out);
      return out;
    }

    // For the element that directly holds a text node.
    function textReason(el) {
      const r = reason(el);
      if (r) return r;
      const cs = getComputedStyle(el);
      if (parseFloat(cs.fontSize) < 2) return "font-size:0";
      const fg = rgba(cs.color);
      if (fg && fg.a === 0) return "transparent text";
      const bg = background(el);
      if (fg && bg && Math.abs(fg.r - bg.r) + Math.abs(fg.g - bg.g) + Math.abs(fg.b - bg.b) < 24) {
        return "text same colour as background";
      }
      return "";
    }

    function block(el) {
      let e = el;
      while (e && e !== document.body) {
        const d = getComputedStyle(e).display;
        if (d && !d.startsWith("inline") && d !== "contents") return e;
        e = e.parentElement;
      }
      return document.body;
    }
    return { textReason, block };
  }

  // ---------------------------------------------------------- extraction
  function clip(s) { return Array.from(s).slice(0, MAX).join(""); }

  function extractChunks() {
    const vis = makeVisibility();
    const chunks = [];
    let cur = null;

    function flush() {
      if (cur) {
        const text = cur.parts.join("").replace(/\s+/g, " ").trim();
        if (text) chunks.push({ text: clip(text), where: cur.reason ? "hidden" : "visible", how: cur.reason,
                                tag: cur.node.tagName.toLowerCase(), node: cur.node });
      }
      cur = null;
    }

    const walker = document.createTreeWalker(document.body || document.documentElement, NodeFilter.SHOW_TEXT, {
      acceptNode(n) {
        for (let e = n.parentElement; e; e = e.parentElement) if (SKIP.has(e.tagName.toUpperCase())) return NodeFilter.FILTER_REJECT;
        return /\S/.test(n.nodeValue) ? NodeFilter.FILTER_ACCEPT : NodeFilter.FILTER_SKIP;
      },
    });
    let count = 0;
    for (let n = walker.nextNode(); n && count < 50000; n = walker.nextNode(), count++) {
      const el = n.parentElement;
      const why = vis.textReason(el);
      const b = vis.block(el);
      if (!cur || cur.block !== b || cur.reason !== why) {
        flush();
        cur = { block: b, reason: why, parts: [], node: el };
      }
      cur.parts.push(n.nodeValue);
    }
    flush();

    // Comments (anywhere, including <head>)
    const cw = document.createTreeWalker(document.documentElement, NodeFilter.SHOW_COMMENT);
    for (let c = cw.nextNode(); c; c = cw.nextNode()) {
      const t = c.nodeValue.replace(/\s+/g, " ").trim();
      if (t.length > 20 && !/^(?:\[if|<!\[endif|#)/.test(t)) {
        chunks.push({ text: clip(t), where: "comment", how: "<!-- -->", tag: "comment", node: c.parentElement });
      }
    }
    // Text attributes
    const sel = PG.textAttrs.map((a) => "[" + a + "]").join(",");
    document.querySelectorAll(sel).forEach((el) => {
      PG.textAttrs.forEach((a) => {
        const v = (el.getAttribute(a) || "").trim();
        if (v.length > 25) chunks.push({ text: clip(v), where: "attribute", how: a, tag: el.tagName.toLowerCase(), node: el });
      });
    });
    // Meta tags
    document.querySelectorAll("meta[name], meta[property]").forEach((m) => {
      const name = (m.getAttribute("name") || m.getAttribute("property") || "").toLowerCase();
      const v = m.getAttribute("content");
      if (META.has(name) && v) chunks.push({ text: clip(v), where: "meta", how: name, tag: "meta", node: null });
    });
    // Structured data
    document.querySelectorAll('script[type*="ld+json" i]').forEach((s) => {
      let data;
      try { data = JSON.parse(s.textContent); } catch (e) { return; }
      const found = [];
      (function walk(node, key) {
        if (found.length >= 200) return;
        if (Array.isArray(node)) node.forEach((v) => walk(v, key));
        else if (node && typeof node === "object") Object.keys(node).forEach((k) => walk(node[k], k));
        else if (typeof node === "string" && node.length > 25 && node.includes(" ") && !node.startsWith("http")) found.push([key, node]);
      })(data, "");
      found.forEach(([k, v]) => chunks.push({ text: clip(v), where: "structured-data", how: k, tag: "script", node: null }));
    });
    // Templates are never shown
    document.querySelectorAll("template").forEach((t) => {
      const v = (t.content.textContent || "").replace(/\s+/g, " ").trim();
      if (v) chunks.push({ text: clip(v), where: "hidden", how: "template (never shown)", tag: "template", node: null });
    });
    // Invisible Unicode tag characters
    const extra = [];
    chunks.forEach((c) => {
      const t = PL.decodeTags(c.text);
      if (t.trim()) extra.push({ text: t, where: "invisible-unicode", how: "Unicode tag characters", tag: c.tag, node: c.node });
    });
    return chunks.concat(extra);
  }

  // ---------------------------------------------------------- scanning
  function scan() {
    const started = performance.now();
    const content = PG.scanChunks(extractChunks());
    const html = document.documentElement.outerHTML;
    const links = PL.scanHtml(html.length > 6e6 ? html.slice(0, 6e6) : html)
      .filter((r) => r.prompt);
    const worst = Math.max(FLAGGED[content.verdict] || 0,
                           ...links.map((r) => FLAGGED[r.verdict] || 0), 0);
    const verdict = worst === 2 ? "DANGEROUS" : worst === 1 ? "SUSPICIOUS" : "LOOKS_SAFE";
    last = { verdict, content, links, url: location.href, ms: Math.round(performance.now() - started) };
    const flaggedCount = content.findings.length + links.filter((r) => FLAGGED[r.verdict]).length;
    const title = verdict === "LOOKS_SAFE" ? "promptlink: nothing hidden for AI found"
      : "promptlink: " + flaggedCount + " thing(s) on this page aimed at AI";
    try { api.runtime.sendMessage({ type: "promptlink:result", verdict, title }); } catch (e) { /* extension reloaded */ }
    return last;
  }

  function publicResult(r) {
    // Strip DOM references before sending to the popup.
    return {
      verdict: r.verdict, url: r.url, ms: r.ms,
      content: { verdict: r.content.verdict, chunks: r.content.chunks, hidden_chunks: r.content.hidden_chunks,
                 findings: r.content.findings.map((f, i) => ({ i, verdict: f.verdict, where: f.where, how: f.how, tag: f.tag,
                   text: f.text, rules: f.findings.filter((x) => !/-weak$|^shape$/.test(x.category)).map((x) => ({ rule: x.rule, description: x.description })),
                   canShow: !!(f.node && f.node.isConnected) })) },
      links: r.links.map((l, i) => ({ i, verdict: l.verdict, assistant: l.assistant, prompt: l.prompt, url: l.url,
                                      rules: l.findings.filter((x) => !/-weak$|^shape$/.test(x.category)).map((x) => ({ rule: x.rule, description: x.description })) })),
    };
  }

  // ---------------------------------------------------------- show on page
  let marked = null;
  function show(kind, i) {
    if (!last) return false;
    let el = null;
    if (kind === "content") el = last.content.findings[i] && last.content.findings[i].node;
    else {
      const url = last.links[i] && last.links[i].url;
      el = Array.from(document.querySelectorAll("a[href]")).find((a) => a.href === url || a.getAttribute("href") === url) || null;
    }
    if (!el || !el.isConnected) return false;
    if (marked) { marked.el.style.outline = marked.outline; marked.el.style.outlineOffset = marked.offset; }
    marked = { el, outline: el.style.outline, offset: el.style.outlineOffset };
    el.style.outline = "3px solid #ec7a6f";
    el.style.outlineOffset = "3px";
    el.scrollIntoView({ behavior: "smooth", block: "center" });
    return true;
  }

  api.runtime.onMessage.addListener((msg, sender, reply) => {
    if (!msg) return;
    if (msg.type === "promptlink:scan") { reply(publicResult(scan())); return; }
    if (msg.type === "promptlink:show") { reply(show(msg.kind, msg.i)); return; }
  });

  // Scan once the page is idle, and again shortly after for buttons that
  // scripts add late. Pages that keep changing are not re-scanned forever.
  scan();
  setTimeout(scan, 4000);
})();
