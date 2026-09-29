// Asks the content script for a fresh scan of the current tab and shows it.
// Page text is inserted with textContent only, never as HTML.
const api = globalThis.browser || globalThis.chrome;
const out = document.getElementById("out");
document.getElementById("ver").textContent = "v" + (globalThis.PROMPTLINK_RULES ? globalThis.PROMPTLINK_RULES.version : "");

const HEAD = {
  DANGEROUS: ["Hidden instructions for AI", "This page tries to steer an AI assistant that reads it. Be careful asking an AI to summarise or act on it."],
  SUSPICIOUS: ["Worth a look", "This page talks to AI in a way that might be an attempt to steer it."],
  LOOKS_SAFE: ["Nothing hidden for AI", "No instructions aimed at AI found on this page."],
};
const WHERE = (globalThis.PROMPTLINK_RULES && globalThis.PROMPTLINK_RULES.page.whereText) || {};

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text != null) e.textContent = text;
  return e;
}

function send(tabId, msg) {
  return new Promise((resolve) => {
    try {
      const p = api.tabs.sendMessage(tabId, msg, (r) => resolve(api.runtime.lastError ? null : r));
      if (p && p.then) p.then(resolve, () => resolve(null));
    } catch (e) { resolve(null); }
  });
}

function item(verdict, label, text, rules, onShow) {
  const box = el("div", "item");
  const top = el("div", "top");
  const left = el("span");
  left.append(el("span", "tag " + verdict, verdict === "DANGEROUS" ? "Dangerous" : verdict === "SUSPICIOUS" ? "Suspicious" : "Looks safe"),
              document.createTextNode(" · " + label));
  top.append(left);
  if (onShow) {
    const b = el("button", null, "Show");
    b.addEventListener("click", onShow);
    top.append(b);
  }
  box.append(top, el("div", "quote", text));
  if (rules.length) {
    const ul = el("ul", "why");
    rules.forEach((r) => ul.append(el("li", null, r.description)));
    box.append(ul);
  }
  return box;
}

function render(r, tabId) {
  out.textContent = "";
  const [h, p] = HEAD[r.verdict];
  const v = el("div", "verdict " + r.verdict);
  const t = el("div");
  t.append(el("h1", null, h), el("p", null, p));
  v.append(el("span", "dot"), t);
  out.append(v);

  if (r.content.findings.length) {
    out.append(el("h2", null, "In the page content"));
    r.content.findings.forEach((f) => {
      const label = (WHERE[f.where] || f.where) + (f.how && f.where === "hidden" ? " (" + f.how + ")" : "");
      const hidden = f.where !== "visible";
      out.append(item(f.verdict, label, f.text, f.rules.filter((x) => !x.rule.startsWith("AIP-003")),
        f.canShow && !hidden ? () => send(tabId, { type: "promptlink:show", kind: "content", i: f.i }) : null));
    });
  }
  const flaggedLinks = r.links.filter((l) => l.verdict !== "LOOKS_SAFE");
  if (flaggedLinks.length) {
    out.append(el("h2", null, "In AI-assistant links"));
    flaggedLinks.forEach((l) => out.append(item(l.verdict, "opens " + l.assistant, l.prompt, l.rules,
      () => send(tabId, { type: "promptlink:show", kind: "link", i: l.i }))));
  }
  const stats = el("p", "stats",
    `Read ${r.content.chunks} text blocks (${r.content.hidden_chunks} hidden from view) and ` +
    `${r.links.length} AI link${r.links.length === 1 ? "" : "s"} with a prompt in ${r.ms} ms.`);
  out.append(stats);
}

(async function () {
  const [tab] = await new Promise((res) => {
    const p = api.tabs.query({ active: true, currentWindow: true }, res);
    if (p && p.then) p.then(res);
  });
  const r = tab ? await send(tab.id, { type: "promptlink:scan" }) : null;
  out.textContent = "";
  if (!r) out.append(el("p", "dim", "promptlink can't read this page. It works on normal web pages; " +
                                     "if this one was open before you installed promptlink, reload it."));
  else render(r, tab.id);
})();
