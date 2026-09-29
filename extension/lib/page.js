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
  var HIDDEN_WHERE = {};
  P.hiddenWhere.forEach(function (w) { HIDDEN_WHERE[w] = true; });
  var ORDER = { LOOKS_SAFE: 0, SUSPICIOUS: 1, DANGEROUS: 2 };
  var KEEP = { memory: 1, trust: 1, override: 1, exfiltration: 1 };

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
    PL.runRules(text).forEach(function (x) { if (KEEP[x.category]) findings.push(x); });
    if (!findings.length) return null;

    var cats = {};
    findings.forEach(function (x) { cats[x.category] = true; });
    var hidden = !!HIDDEN_WHERE[chunk.where];
    var addressed = !!cats.addressed;
    var orders = cats.instruction || cats.memory || cats.trust || cats.override || cats.exfiltration;
    var ordersBesidesOverride = cats.instruction || cats.memory || cats.trust || cats.exfiltration;
    var strong = cats.override || cats.exfiltration || cats.memory;
    var total = findings.reduce(function (a, x) { return a + x.weight; }, 0);
    if (hidden) {
      findings.push(f("AIP-003", "hidden", 2, "Visitors can't see it (" + P.whereText[chunk.where] + ": " + chunk.how + ")", chunk.where));
      total += 2;
    }
    var verdict;
    if (addressed && orders && hidden) verdict = "DANGEROUS";
    else if (hidden && (cats.exfiltration || (cats.override && (ordersBesidesOverride || addressed)))) verdict = "DANGEROUS";
    else if (hidden && (addressed || strong)) verdict = "SUSPICIOUS";
    else if (addressed && (strong || cats.instruction)) verdict = "SUSPICIOUS";
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

  var api = { analyseChunk: analyseChunk, scanChunks: scanChunks, whereText: P.whereText,
              metaNames: P.metaNames, textAttrs: P.textAttrs, srClasses: P.srClasses };
  g.promptlinkPage = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
