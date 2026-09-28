// Reads a JSON list of inputs on stdin, runs the web engine, prints results.
// Used by tests/test_web_parity.py. Not needed to use promptlink.
const path = require("path");
require(path.join(__dirname, "..", "docs", "rules.js"));
const pl = require(path.join(__dirname, "..", "docs", "promptlink.js"));

let input = "";
process.stdin.on("data", (d) => (input += d));
process.stdin.on("end", () => {
  const cases = JSON.parse(input);
  const out = cases.map((c) =>
    c.kind === "html" ? pl.scanHtml(c.value) : pl.checkUrl(c.value));
  process.stdout.write(JSON.stringify(out));
});
