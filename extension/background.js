// Sets the toolbar badge from what the content script found. Nothing is
// stored and nothing is sent anywhere.
const api = globalThis.browser || globalThis.chrome;

const BADGE = {
  DANGEROUS: { text: "!", color: "#d9534f" },
  SUSPICIOUS: { text: "?", color: "#c9962e" },
};

api.runtime.onMessage.addListener((msg, sender) => {
  if (!msg || msg.type !== "promptlink:result" || !sender.tab) return;
  const tabId = sender.tab.id;
  const b = BADGE[msg.verdict];
  api.action.setBadgeText({ tabId, text: b ? b.text : "" });
  if (b) api.action.setBadgeBackgroundColor({ tabId, color: b.color });
  api.action.setTitle({ tabId, title: msg.title || "promptlink" });
});
