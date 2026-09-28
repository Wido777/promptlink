// promptlink web engine: a line-by-line port of promptlink/detector.py.
// The detection RULES are not duplicated here; they are generated from the
// Python source into rules.js. tests/test_web_parity.py checks that this
// file and the Python version give identical results.
(function (g) {
  "use strict";

  var R = g.PROMPTLINK_RULES || (typeof require !== "undefined" ? require("./rules.js") : null);
  if (!R) throw new Error("rules.js must be loaded before promptlink.js");

  var WORD = "\\p{L}\\p{N}_";
  var TAG_START = 0xE0000, TAG_END = 0xE0080;
  var BIDI = {};
  [0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069].forEach(function (c) {
    BIDI[String.fromCodePoint(c)] = true;
  });

  var COMPILED = R.rules.map(function (r) {
    return { id: r.id, category: r.category, weight: r.weight, description: r.description,
             patterns: r.patterns.map(function (p) { return new RegExp(p, "u"); }) };
  });
  var SUMMARY_REQUEST = new RegExp(R.summaryRequest, "u");
  var URL_IN_TEXT = /https?:\/\/[^\s"'<>]+|www\.[^\s"'<>]+/gi;
  var BASE64_BLOB = /(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])/g;
  var LEET = new RegExp(
    "(?:(?<![" + WORD + "])(?=[" + WORD + "]))(?:[" + WORD + "][.\\-_*]){3,}[" + WORD + "]" +
    "(?:(?<=[" + WORD + "])(?![" + WORD + "]))", "gu");
  var HAS_SCHEME = /^[a-z][a-z0-9+.-]*:\/\//i;
  var LOOKS_URL = /^\s*https?:\/\//i;
  var LOOKS_HOST = new RegExp("^\\s*(?:https?://)?[" + WORD + ".-]+\\.[a-z]{2,}", "iu");

  // ---------------------------------------------------------------- helpers
  function cp(s) { return Array.from(s); }            // code points, like Python str
  function cpLen(s) { return cp(s).length; }

  // Python urllib.parse.unquote: decode %XX runs as UTF-8, replace bad bytes.
  function unquote(s) {
    if (s.indexOf("%") === -1) return s;
    return s.replace(/(?:%[0-9a-fA-F]{2})+/g, function (run) {
      var bytes = new Uint8Array(run.length / 3);
      for (var i = 0; i < bytes.length; i++) bytes[i] = parseInt(run.substr(i * 3 + 1, 2), 16);
      return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
    });
  }

  // Python urllib.parse.parse_qsl(qs, keep_blank_values=False)
  function parseQsl(qs) {
    var out = [];
    if (!qs) return out;
    qs.split("&").forEach(function (part) {
      if (!part) return;
      var eq = part.indexOf("=");
      if (eq === -1) return;
      var name = part.slice(0, eq), value = part.slice(eq + 1);
      if (!value.length) return;
      out.push([unquote(name.replace(/\+/g, " ")), unquote(value.replace(/\+/g, " "))]);
    });
    return out;
  }

  // Python urllib.parse.urlsplit (the parts promptlink uses)
  function urlsplit(url) {
    url = url.replace(/[\t\r\n]/g, "");
    var scheme = "", netloc = "", query = "", fragment = "";
    var m = /^([a-zA-Z][a-zA-Z0-9+.-]*):/.exec(url);
    if (m) { scheme = m[1].toLowerCase(); url = url.slice(m[0].length); }
    if (url.slice(0, 2) === "//") {
      var rest = url.slice(2), end = rest.length;
      for (var i = 0; i < rest.length; i++) { if ("/?#".indexOf(rest[i]) !== -1) { end = i; break; } }
      netloc = rest.slice(0, end); url = rest.slice(end);
    }
    var h = url.indexOf("#");
    if (h !== -1) { fragment = url.slice(h + 1); url = url.slice(0, h); }
    var q = url.indexOf("?");
    if (q !== -1) { query = url.slice(q + 1); url = url.slice(0, q); }
    var host = netloc;
    var at = host.lastIndexOf("@");
    if (at !== -1) host = host.slice(at + 1);
    if (host[0] === "[") { host = host.slice(1, host.indexOf("]") === -1 ? host.length : host.indexOf("]")); }
    else if (host.indexOf(":") !== -1) host = host.slice(0, host.indexOf(":"));
    return { scheme: scheme, hostname: host.toLowerCase() || null, path: url, query: query, fragment: fragment };
  }

  function lstripChars(s, chars) { var i = 0; while (i < s.length && chars.indexOf(s[i]) !== -1) i++; return s.slice(i); }
  function stripChars(s, chars) {
    s = lstripChars(s, chars); var j = s.length;
    while (j > 0 && chars.indexOf(s[j - 1]) !== -1) j--; return s.slice(0, j);
  }

  function params(parts) {
    var pairs = parseQsl(parts.query);
    if (parts.fragment && parts.fragment.indexOf("=") !== -1) {
      pairs = pairs.concat(parseQsl(lstripChars(parts.fragment, "/?")));
    }
    return pairs;
  }

  function lowerMap(pairs) {
    var m = {};
    pairs.forEach(function (p) { m[p[0].toLowerCase()] = p[1]; });
    return m;
  }

  function hostMatch(host, path, pairs) {
    host = (host || "").toLowerCase().replace(/\.+$/, "");
    if (host.indexOf("www.") === 0) host = host.slice(4);
    var names = Object.keys(R.assistantHosts);
    for (var i = 0; i < names.length; i++) {
      var known = names[i];
      if (host === known || host.endsWith("." + known)) return R.assistantHosts[known];
    }
    var p = lowerMap(pairs);
    for (var j = 0; j < R.pathAssistants.length; j++) {
      var a = R.pathAssistants[j];
      if (host === a.host && path.toLowerCase().indexOf(a.prefix) === 0) {
        if (a.required === null || p[a.required[0]] === a.required[1]) return a.name;
      }
    }
    return null;
  }

  function fullUnquote(value) {
    var rounds = 0;
    for (var i = 0; i < 4; i++) {
      var d = unquote(value);
      if (d === value) break;
      value = d; rounds++;
    }
    return [value, rounds];
  }

  function findPrompt(url, depth, trail) {
    depth = depth || 0; trail = (trail || []).slice();
    url = stripChars(url.trim(), "<>\"'");
    if (!HAS_SCHEME.test(url)) url = "https://" + url;
    var parts = urlsplit(url);
    var pairs = params(parts);
    var assistant = hostMatch(parts.hostname || "", parts.path, pairs);
    if (assistant) {
      var lowered = lowerMap(pairs);
      for (var i = 0; i < R.promptParams.length; i++) {
        var p = R.promptParams[i];
        if (Object.prototype.hasOwnProperty.call(lowered, p) && lowered[p].trim()) {
          return [assistant, p, lowered[p], trail];
        }
      }
      return [assistant, null, null, trail];
    }
    if (depth >= 3) return null;
    for (var k = 0; k < pairs.length; k++) {
      var key = pairs[k][0], decoded = pairs[k][1];
      for (var n = 0; n < 3; n++) { if (LOOKS_URL.test(decoded)) break; decoded = unquote(decoded); }
      if (R.nestedUrlParams.indexOf(key.toLowerCase()) !== -1 || LOOKS_URL.test(decoded)) {
        if (LOOKS_HOST.test(decoded)) {
          var hit = findPrompt(decoded, depth + 1, trail.concat([url]));
          if (hit && hit[0]) return hit;
        }
      }
    }
    return null;
  }

  // ------------------------------------------------------------ text checks
  function isTag(ch) { var c = ch.codePointAt(0); return c >= TAG_START && c < TAG_END; }
  function isHidden(ch) { return Object.prototype.hasOwnProperty.call(R.zeroWidth, ch) || BIDI[ch] || isTag(ch); }

  function hiddenCharacters(text) {
    var found = [];
    for (var ch of text) {
      if (Object.prototype.hasOwnProperty.call(R.zeroWidth, ch)) found.push(R.zeroWidth[ch]);
      else if (BIDI[ch]) found.push("BIDI CONTROL U+" + ch.codePointAt(0).toString(16).toUpperCase().padStart(4, "0"));
      else if (isTag(ch)) found.push("UNICODE TAG CHARACTER");
    }
    return found;
  }

  function decodeTags(text) {
    var out = "";
    for (var ch of text) if (isTag(ch)) out += String.fromCodePoint(ch.codePointAt(0) - TAG_START);
    return out;
  }

  function normalise(text) {
    text = text.normalize("NFKC");
    var kept = "";
    for (var ch of text) if (!isHidden(ch)) kept += ch;
    kept = kept.replace(LEET, function (m) { return m.replace(/[.\-_*]/g, ""); });
    kept = kept.replace(/\s+/g, " ");
    return kept.toLowerCase().trim();
  }

  function isPrintable(ch) {
    if (ch === " ") return true;
    return !/[\p{C}\p{Z}]/u.test(ch);
  }

  function decodeBase64Blobs(text) {
    var out = [], blobs = text.match(BASE64_BLOB) || [];
    blobs.forEach(function (blob) {
      var padded = blob + "=".repeat((4 - blob.length % 4) % 4);
      var decoded;
      try {
        if (!/^[A-Za-z0-9+/]*={0,2}$/.test(padded) || padded.length % 4 !== 0) return;
        var bin = atob(padded);
        var bytes = new Uint8Array(bin.length);
        for (var i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
        decoded = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
      } catch (e) { return; }
      var chars = cp(decoded), printable = 0;
      chars.forEach(function (c) { if (isPrintable(c)) printable++; });
      if (printable / Math.max(chars.length, 1) > 0.9 && /[a-z]{3,} [a-z]{3,}/.test(decoded.toLowerCase())) {
        out.push(decoded);
      }
    });
    return out;
  }

  function finding(rule, category, weight, description, evidence) {
    return { rule: rule, category: category, weight: weight, description: description, evidence: evidence };
  }

  function runRules(text, source) {
    var out = [];
    COMPILED.forEach(function (rule) {
      for (var i = 0; i < rule.patterns.length; i++) {
        var m = rule.patterns[i].exec(text);
        if (m) {
          var start = Math.max(m.index - 25, 0), end = Math.min(m.index + m[0].length + 25, text.length);
          out.push(finding(rule.id, rule.category, rule.weight, rule.description,
                           (source ? "[" + source + "] " : "") + "…" + text.slice(start, end) + "…"));
          break;
        }
      }
    });
    return out;
  }

  function analysePrompt(prompt) {
    var findings = [], notes = [];
    var hidden = hiddenCharacters(prompt);
    if (hidden.length) {
      var kinds = Array.from(new Set(hidden)).sort();
      findings.push(finding("HID-001", "obfuscation", 3, "Contains invisible or direction-changing characters",
                            hidden.length + " hidden character(s): " + kinds.join(", ")));
      var tagText = decodeTags(prompt);
      if (tagText.trim()) {
        notes.push("Invisible tag characters spell out: '" + tagText + "'");
        findings = findings.concat(runRules(normalise(tagText), "hidden text"));
      }
    }
    var text = normalise(prompt);
    findings = findings.concat(runRules(text, ""));
    decodeBase64Blobs(prompt).forEach(function (decoded) {
      findings.push(finding("ENC-001", "obfuscation", 2, "Contains a base64-encoded text payload",
                            "decodes to: " + cp(decoded).slice(0, 120).join("")));
      findings = findings.concat(runRules(normalise(decoded), "base64"));
    });
    if (SUMMARY_REQUEST.test(text) && findings.some(function (f) { return f.category === "memory" || f.category === "trust"; })) {
      findings.push(finding("SHP-001", "shape", 1, "Looks like a 'Summarize with AI' button carrying extra instructions",
                            "summary request combined with memory/trust directives"));
    }
    var urls = prompt.match(URL_IN_TEXT) || [];
    if (urls.length) notes.push("Links mentioned in the prompt: " + urls.slice(0, 5).map(function (u) { return cp(u).slice(0, 80).join(""); }).join(", "));
    var n = cpLen(prompt);
    if (n > 600) notes.push("Unusually long prompt (" + n + " characters) for a one-click link");

    var seen = {}, unique = [];
    findings.forEach(function (f) { if (!seen[f.rule]) { seen[f.rule] = true; unique.push(f); } });
    return [unique, notes];
  }

  function score(findings) {
    var cats = {};
    findings.forEach(function (f) { cats[f.category] = true; });
    var subsumed = { "memory-weak": "memory", "trust-weak": "trust" };
    var total = 0;
    findings.forEach(function (f) {
      if (!(subsumed[f.category] && cats[subsumed[f.category]])) total += f.weight;
    });
    if (cats.memory && cats.trust) total += 3;
    if (cats.exfiltration) total += 3;
    if (cats.override && (cats.memory || cats.trust || cats.exfiltration)) total += 2;
    var verdict = (cats.exfiltration || total >= 7) ? "DANGEROUS" : total >= 4 ? "SUSPICIOUS" : "LOOKS_SAFE";
    return [total, verdict];
  }

  function checkUrl(url) {
    var rep = { url: url, assistant: null, prompt: null, param: null, unwrapped_from: [],
                findings: [], score: 0, verdict: "NOT_ASSISTANT_LINK", notes: [] };
    var hit = findPrompt(url);
    if (!hit) {
      rep.notes.push("Not a recognised AI-assistant link, and no assistant link found inside it.");
      return rep;
    }
    rep.assistant = hit[0]; rep.unwrapped_from = hit[3];
    if (hit[3].length) rep.notes.push("The real destination was hidden inside " + hit[3].length + " wrapper link(s).");
    if (hit[2] === null) {
      rep.verdict = "NO_PROMPT";
      rep.notes.push("Opens " + hit[0] + " but carries no pre-filled prompt.");
      return rep;
    }
    var u = fullUnquote(hit[2]);
    if (u[1] >= 1) rep.findings.push(finding("ENC-002", "obfuscation", 1, "Prompt was percent-encoded more than once",
                                             "decoded " + (u[1] + 1) + " times"));
    rep.prompt = u[0]; rep.param = hit[1];
    var a = analysePrompt(u[0]);
    rep.findings = rep.findings.concat(a[0]);
    rep.notes = rep.notes.concat(a[1]);
    var s = score(rep.findings);
    rep.score = s[0]; rep.verdict = s[1];
    return rep;
  }

  // ------------------------------------------------------------- HTML scan
  var ENTITIES = { amp: "&", lt: "<", gt: ">", quot: "\"", apos: "'", nbsp: " " };
  function unescapeHtml(s) {
    return s.replace(/&(#x[0-9a-f]+|#[0-9]+|[a-z]+);?/gi, function (m, e) {
      if (e[0] === "#") {
        var c = e[1].toLowerCase() === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10);
        try { return String.fromCodePoint(c); } catch (err) { return m; }
      }
      var k = e.toLowerCase();
      return Object.prototype.hasOwnProperty.call(ENTITIES, k) ? ENTITIES[k] : m;
    });
  }

  var HREF = /(?:href|src|action|data-href|data-url)\s*=\s*(["'])([\s\S]*?)\1/gi;
  function extractLinks(html) {
    var links = [], m;
    HREF.lastIndex = 0;
    while ((m = HREF.exec(html)) !== null) links.push(unescapeHtml(m[2]));
    (html.match(URL_IN_TEXT) || []).forEach(function (u) { if (links.indexOf(u) === -1) links.push(u); });
    var out = [], seen = {};
    links.forEach(function (l) { l = l.trim(); if (l && !seen[l]) { seen[l] = true; out.push(l); } });
    return out;
  }

  function scanHtml(html) {
    var reps = [];
    extractLinks(html).forEach(function (link) {
      if (!/^(?:https?:)?\/\/|^www\./i.test(link)) return;
      var rep = checkUrl(link.indexOf("//") === 0 ? "https:" + link : link);
      if (rep.assistant) reps.push(rep);
    });
    return reps;
  }

  var api = { version: R.version, checkUrl: checkUrl, scanHtml: scanHtml, extractLinks: extractLinks,
              analysePrompt: analysePrompt, isHidden: isHidden };
  g.promptlink = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
