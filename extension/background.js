// Calls the PhishShield backend from the service worker, so Gmail's page CORS rules don't apply.
// Set the API URL on the extension's Options page (chrome://extensions → Details → Extension options).
// Local dev default points at this repo's server; after `stripe projects share`, paste the public URL.
const DEFAULT_API = "http://127.0.0.1:3000/api/analyze";
chrome.runtime.onMessage.addListener((msg, _sender, reply) => {
  if (msg.type !== "CHECK_EMAIL") return;
  chrome.storage.sync.get({ api: DEFAULT_API }, async ({ api }) => {
    try {
      const res = await fetch(api, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ emailText: msg.emailText })
      });
      reply({ ok: true, result: await res.json() });
    } catch (e) {
      reply({ ok: false, error: String(e) });
    }
  });
  return true; // keep channel open for async reply
});
