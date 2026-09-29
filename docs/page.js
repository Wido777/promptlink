// promptlink page engine: a port of analyse_chunk / scan_chunks from
// promptlink/page.py. Patterns come from rules.js (generated from Python);
// tests/test_web_parity.py checks both versions agree on every chunk.
//
// A "chunk" is { text, where, how, tag }. Where the text came from (hidden
// element, comment, alt text...) is decided by whoever extracts the chunks:
// the extension reads the live, rendered page for that.
(function (g) {
  "use strict";

  var R = g.PROMPTLINK_RULES || (typeof require !== "undefined" ? require("./rules.js") : null);
  var PL = g.promptlink || (typeof require !== "undefined" ? require("./promptlink.js") : null);
  if (!R || !PL) throw new Error("load rules.js and promptlink.js before page.js");

  var P = R.page;
  var ADDRESS = new RegExp(P.address, "iu");
  var INSTRUCT = new RegExp(P.instruct, "iu");
  var QUICK = new RegExp(P.quick, "iu");
  var OVERRIDE = new RegExp(P.override, "iu");
  var HIDDEN_WHERE = {};
  P.hiddenWhere.forEach(function (w) { HIDDEN_WHERE[w] = true; });
  var ORDER = { LOOKS_SAFE: 0, SUSPICIOUS: 1, DANGEROUS: 2 };
  var KEEP = { memory: 1, trust: 1, exfiltration: 1 };

  function cpSlice(s, n) { return Array.from(s).slice(0, n).join(""); }

  function snippet(text, m) {
    var s = Math.max(m.index - 30, 0), e = Math.min(m.index + m[0].length + 30, text.length);
    return "…" + text.slice(s, e) + "…";
  }

  function f(rule, category, weight, description, evidence) {
    return { rule: rule, category: category, weight: weight, description: description, evidence: evidence };
  }

  function analyseChunk(chunk) {
    var raw = chunk.text;
    if (!QUICK.test(raw) && PL.hiddenCharacters(raw).length === 0) return null;
    var text = PL.normalise(raw);
    var findings = [], m;
    if ((m = ADDRESS.exec(text))) findings.push(f("AIP-001", "addressed", 3, "Speaks directly to an AI reading the page", snippet(text, m)));
    if ((m = INSTRUCT.exec(text))) findings.push(f("AIP-002", "instruction", 2, "Gives orders about what to say or do", snippet(text, m)));
    if ((m = OVERRIDE.exec(text))) findings.push(f("AIP-004", "override", 3, "Tries to override the AI's instructions or hide things from the user", snippet(text, m)));
    PL.runRules(text).forEach(function (x) { if (KEEP[x.category]) findings.push(x); });
    if (!findings.length) return null;

    var cats = {};
    findings.forEach(function (x) { cats[x.category] = true; });
    var hidden = !!HIDDEN_WHERE[chunk.where];
    var addressed = !!cats.addressed;
    var orders = cats.instruction || cats.memory || cats.trust || cats.override || cats.exfiltration;
    var ordersBesidesOverride = cats.instruction || cats.memory || cats.trust || cats.exfiltration;
    var total = findings.reduce(function (a, x) { return a + x.weight; }, 0);
    if (hidden) {
      findings.push(f("AIP-003", "hidden", 2, "Visitors can't see it (" + P.whereText[chunk.where] + ": " + chunk.how + ")", chunk.where));
      total += 2;
    }
    var verdict;
    if (hidden && addressed && orders) verdict = "DANGEROUS";
    else if (hidden && cats.override && ordersBesidesOverride) verdict = "DANGEROUS";
    else if (hidden && cats.override) verdict = "SUSPICIOUS";
    else if (addressed && orders) verdict = "SUSPICIOUS";
    else return null;
    return { where: chunk.where, how: chunk.how, tag: chunk.tag, text: cpSlice(raw, 600),
             verdict: verdict, score: total, findings: findings, node: chunk.node || null };
  }

  function scanChunks(chunks) {
    var rep = { verdict: "LOOKS_SAFE", score: 0, findings: [], chunks: chunks.length,
                hidden_chunks: chunks.filter(function (c) { return HIDDEN_WHERE[c.where]; }).length };
    var seen = {};
    chunks.forEach(function (c) {
      var key = cpSlice(PL.normalise(c.text), 300);
      if (seen[key]) return;
      seen[key] = true;
      var x = analyseChunk(c);
      if (x) rep.findings.push(x);
    });
    rep.findings = rep.findings.map(function (x, i) { return [x, i]; }).sort(function (a, b) {
      return (ORDER[b[0].verdict] - ORDER[a[0].verdict]) || (b[0].score - a[0].score) || (a[1] - b[1]);
    }).map(function (p) { return p[0]; });
    if (rep.findings.length) { rep.verdict = rep.findings[0].verdict; rep.score = rep.findings[0].score; }
    return rep;
  }

  // ------------------------------------------------------------------
  // Pasted page code -> chunks. A port of promptlink/page.py's _Extractor
  // (the crawler's view of a page: inline styles, <style> classes, hidden
  // attributes, comments, alt/title text, meta tags, JSON-LD). Works on a
  // string with a small tokenizer, so nothing in the pasted page is ever
  // parsed into a live document, loaded or run.
  var HIDDEN_STYLE = P.hiddenStyle.map(function (p) { return [new RegExp(p[0], "u"), p[1]]; });
  var SAME_COLOUR = P.sameColour.map(function (p) { return new RegExp(p, "u"); });
  function set(list) { var o = {}; list.forEach(function (x) { o[x] = true; }); return o; }
  var SR = set(P.srClasses), HIDE = set(P.hideClasses), SKIP = set(P.skipTags), VOID = set(P.voidTags),
      BLOCK = set(P.blockTags), META = set(P.metaNames);

  var ENT = { amp: "&", lt: "<", gt: ">", quot: "\"", apos: "'", nbsp: "\u00a0", copy: "\u00a9", reg: "\u00ae",
              hellip: "\u2026", mdash: "\u2014", ndash: "\u2013", lsquo: "\u2018", rsquo: "\u2019",
              ldquo: "\u201c", rdquo: "\u201d", laquo: "\u00ab", raquo: "\u00bb", eacute: "\u00e9",
              egrave: "\u00e8", agrave: "\u00e0", ccedil: "\u00e7", euro: "\u20ac", middot: "\u00b7",
              bull: "\u2022", trade: "\u2122", times: "\u00d7", zwj: "\u200d", zwnj: "\u200c", shy: "\u00ad" };
  function unescapeHtml(s) {
    return s.replace(/&(#[xX][0-9a-fA-F]+|#[0-9]+|[a-zA-Z][a-zA-Z0-9]*);?/g, function (m, e) {
      if (e[0] === "#") {
        var c = e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
        if (!(c > 0 && c <= 0x10FFFF)) return "\uFFFD";
        try { return String.fromCodePoint(c); } catch (err) { return m; }
      }
      return Object.prototype.hasOwnProperty.call(ENT, e) ? ENT[e] : m;
    });
  }
  function collapse(s) { return s.replace(/\s+/g, " ").trim(); }

  function styleReason(style) {
    for (var i = 0; i < HIDDEN_STYLE.length; i++) if (HIDDEN_STYLE[i][0].test(style)) return HIDDEN_STYLE[i][1];
    for (var j = 0; j < SAME_COLOUR.length; j++) if (SAME_COLOUR[j].test(style)) return "text same colour as background";
    return "";
  }

  function hiddenFromCss(css) {
    var out = {}, m, rule = /([^{}]+)\{([^{}]*)\}/g;
    while ((m = rule.exec(css)) !== null) {
      var reason = styleReason(m[2].toLowerCase());
      if (!reason) continue;
      m[1].split(",").forEach(function (sel) {
        var k = /^(?:[a-z0-9]+)?([.#])([\p{L}\p{N}_-]+)$/iu.exec(sel.trim());
        if (k) out[k[1] + k[2].toLowerCase()] = reason;
      });
    }
    return out;
  }

  var ATTR = /([^\s"'>\/=]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
  function parseAttrs(s) {
    var out = [], m;
    ATTR.lastIndex = 0;
    while ((m = ATTR.exec(s)) !== null) {
      var v = m[2] !== undefined ? m[2] : m[3] !== undefined ? m[3] : m[4];
      out.push([m[1].toLowerCase(), v === undefined ? "" : unescapeHtml(v)]);
    }
    return out;
  }

  function extractChunks(html) {
    var cssParts = [], sm, styleRx = /<style[^>]*>([\s\S]*?)<\/style>/gi;
    while ((sm = styleRx.exec(html)) !== null) cssParts.push(sm[1]);
    var cssHidden = hiddenFromCss(cssParts.join(" ").toLowerCase());
    var stack = [], skip = 0, skipTag = "", jsonld = false, jsonBuf = [], buf = [];
    var bufKey = ["visible", "", ""], chunks = [];

    function current() {
      for (var i = stack.length - 1; i >= 0; i--) if (stack[i][1]) return ["hidden", stack[i][1], stack[i][0]];
      return ["visible", "", stack.length ? stack[stack.length - 1][0] : ""];
    }
    function flush() {
      var text = collapse(buf.join(""));
      if (text) chunks.push({ text: cpSlice(text, 4000), where: bufKey[0], how: bufKey[1], tag: bufKey[2] });
      buf = [];
    }
    function rekey() {
      var k = current();
      if (k[0] !== bufKey[0] || k[1] !== bufKey[1]) { flush(); bufKey = k; }
    }
    function elementReason(tag, a) {
      if (Object.prototype.hasOwnProperty.call(a, "hidden")) return "hidden attribute";
      if (tag === "template") return "template (never shown)";
      if ((a.type || "").toLowerCase() === "hidden") return "hidden input";
      var r = styleReason((a.style || "").toLowerCase());
      if (r) return r;
      var classes = (a["class"] || "").toLowerCase().split(/\s+/).filter(Boolean);
      for (var i = 0; i < classes.length; i++) {
        var c = classes[i];
        if (SR[c]) return "screen-reader-only class";
        if (HIDE[c]) return "hidden class";
        if (cssHidden["." + c]) return cssHidden["." + c] + " (stylesheet)";
      }
      if (a.id && cssHidden["#" + a.id.toLowerCase()]) return cssHidden["#" + a.id.toLowerCase()] + " (stylesheet)";
      return "";
    }
    function jsonldChunks(raw) {
      var data;
      try { data = JSON.parse(raw); } catch (e) { return; }
      var texts = [];
      (function walk(node, key) {
        if (Array.isArray(node)) node.forEach(function (v) { walk(v, key); });
        else if (node && typeof node === "object") Object.keys(node).forEach(function (k) { walk(node[k], k); });
        else if (typeof node === "string" && Array.from(node).length > 25 && node.indexOf(" ") !== -1 && node.indexOf("http") !== 0) texts.push([key, node]);
      })(data, "");
      texts.slice(0, 200).forEach(function (t) { chunks.push({ text: cpSlice(t[1], 4000), where: "structured-data", how: t[0], tag: "script" }); });
    }
    function startTag(tag, pairs, selfClosing) {
      var a = {};
      pairs.forEach(function (p) { if (!Object.prototype.hasOwnProperty.call(a, p[0])) a[p[0]] = p[1]; });
      if (skip) { if (tag === skipTag && !VOID[tag]) skip++; return; }
      if (tag === "script" && (a.type || "").toLowerCase().indexOf("ld+json") !== -1) { jsonld = true; jsonBuf = []; return; }
      if (SKIP[tag]) { skip = 1; skipTag = tag; return; }
      if (tag === "meta") {
        var name = (a.name || a.property || "").toLowerCase();
        if (META[name] && a.content) chunks.push({ text: cpSlice(a.content, 4000), where: "meta", how: name, tag: "meta" });
        return;
      }
      P.textAttrs.forEach(function (at) {
        var v = (a[at] || "").trim();
        if (Array.from(v).length > 25) chunks.push({ text: cpSlice(v, 4000), where: "attribute", how: at, tag: tag });
      });
      if (BLOCK[tag]) flush();
      if (VOID[tag]) return;
      stack.push([tag, elementReason(tag, a)]);
      rekey();
      if (selfClosing && stack.length && stack[stack.length - 1][0] === tag && !skip) endTag(tag);
    }
    function endTag(tag) {
      if (jsonld && tag === "script") { jsonld = false; jsonldChunks(jsonBuf.join("")); return; }
      if (skip) { if (tag === skipTag) skip--; return; }
      if (VOID[tag]) return;
      if (!stack.some(function (s) { return s[0] === tag; })) return;
      if (BLOCK[tag]) flush();
      while (stack.length) { if (stack.pop()[0] === tag) break; }
      rekey();
    }
    function data(text) {
      if (jsonld) { jsonBuf.push(text); return; }
      if (skip) return;
      buf.push(text);
    }
    function comment(text) {
      if (skip) return;
      var t = collapse(text);
      if (Array.from(t).length > 20 && !/^(?:\[if|<!\[endif|#)/.test(t)) chunks.push({ text: cpSlice(t, 4000), where: "comment", how: "<!-- -->", tag: "comment" });
    }

    var TOKEN = /<!--([\s\S]*?)(?:-->|$)|<![^>]*>|<\?[^>]*>|<\/([a-zA-Z][^\s\/>]*)[^>]*>|<([a-zA-Z][^\s\/>]*)((?:[^>"']|"[^"]*"|'[^']*')*?)(\/?)>/g;
    var pos = 0, m;
    while ((m = TOKEN.exec(html)) !== null) {
      if (m.index > pos) data(unescapeHtml(html.slice(pos, m.index)));
      pos = TOKEN.lastIndex;
      if (m[1] !== undefined && m[0].indexOf("<!--") === 0) comment(m[1]);
      else if (m[2] !== undefined) endTag(m[2].toLowerCase());
      else if (m[3] !== undefined) {
        var tag = m[3].toLowerCase();
        startTag(tag, parseAttrs(m[4] || ""), m[5] === "/");
        if ((tag === "script" || tag === "style") && m[5] !== "/") {        // raw text until the close tag
          var close = new RegExp("</" + tag + "\\s*>", "ig");
          close.lastIndex = pos;
          var c = close.exec(html), end = c ? c.index : html.length;
          if (end > pos) data(html.slice(pos, end));
          if (c) { endTag(tag); pos = close.lastIndex; } else pos = html.length;
          TOKEN.lastIndex = pos;
        }
      }
      if (m[0] === "") TOKEN.lastIndex++;
    }
    if (pos < html.length) data(unescapeHtml(html.slice(pos)));
    flush();

    var extra = [];
    chunks.forEach(function (c) {
      var t = PL.decodeTags(c.text);
      if (t.trim()) extra.push({ text: t, where: "invisible-unicode", how: "Unicode tag characters", tag: c.tag });
    });
    return chunks.concat(extra);
  }

  function scanPageHtml(html) { return scanChunks(extractChunks(html)); }

  var api = { analyseChunk: analyseChunk, scanChunks: scanChunks, extractChunks: extractChunks, scanPageHtml: scanPageHtml,
              whereText: P.whereText,
              metaNames: P.metaNames, textAttrs: P.textAttrs, srClasses: P.srClasses };
  g.promptlinkPage = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
