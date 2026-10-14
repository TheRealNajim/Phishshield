// Watches Gmail for an opened message, ships it to PhishShield as raw email text,
// and renders the sandbox verdict as a badge. Adapted from the email-verifier starter.
// Gmail's class names (gD, hP, a3s, adn) change sometimes; update them here if badges stop appearing.
const seen = new Set();

async function fetchRawSource(legacyId) {
  // Best effort: Gmail's "Show original" view, which carries the real headers
  // (Authentication-Results for SPF/DKIM/DMARC — the checks that matter most).
  if (!legacyId) return null;
  try {
    const base = location.origin + location.pathname;
    const r = await fetch(`${base}?view=om&permmsgid=msg-f:${legacyId}`, { credentials: "include" });
    if (!r.ok) return null;
    const text = await r.text();
    return text.includes("Received:") ? text : null;
  } catch { return null; }
}

function collect(container) {
  const senderEl = container.querySelector("span.gD[email]");
  const bodyEl = container.querySelector("div.a3s");
  const links = [...(bodyEl?.querySelectorAll("a[href]") || [])].map(a => ({
    text: a.innerText.trim().slice(0, 200).replace(/"/g, "'"),
    href: a.href
  }));
  return {
    senderEmail: senderEl?.getAttribute("email") || "",
    senderName: senderEl?.getAttribute("name") || senderEl?.innerText || "",
    subject: document.querySelector("h2.hP")?.innerText || "",
    body: (bodyEl?.innerText || "").slice(0, 20000),
    links
  };
}

// The sandbox engine parses these machine-readable lines for display-text vs
// destination mismatch (e.g. shows chase.com, goes to evil IP).
function toEmailText(p, rawSource) {
  if (rawSource) return rawSource;
  const head = `From: ${p.senderName} <${p.senderEmail}>\nSubject: ${p.subject}\nContent-Type: text/html; charset="utf-8"\n\n${p.body}\n`;
  const linkLines = p.links.map(l => `[[LINK text="${l.text}" href="${l.href}"]]`).join("\n");
  return head + (linkLines ? "\n" + linkLines + "\n" : "");
}

function renderBadge(container, result) {
  container.querySelector(".ev-badge")?.remove();
  const badge = document.createElement("div");
  const v = result.verdict || "Suspicious";
  badge.className = "ev-badge " + (v === "Verified" ? "ev-ok" : v === "Malicious" ? "ev-bad" : "ev-warn");
  const icon = v === "Verified" ? "✔ Verified" : v === "Malicious" ? "⛔ Malicious" : "⚠ Suspicious";
  badge.innerHTML = `<strong>${icon}</strong> <span style="opacity:.65;font-weight:400">by PhishShield sandbox</span>
    <span class="ev-score">risk ${result.score ?? "?"}/100</span>
    <ul>${(result.reasons || []).map(r => `<li>${String(r).replace(/</g, "&lt;")}</li>`).join("")}</ul>`;
  badge.addEventListener("click", () => badge.classList.toggle("ev-open"));
  container.prepend(badge);
}

async function check(container) {
  const id = container.getAttribute("data-legacy-message-id") || container.dataset.messageId;
  const key = id || container.innerText.slice(0, 80);
  if (seen.has(key)) return;
  seen.add(key);
  const payload = collect(container);
  if (!payload.senderEmail) { seen.delete(key); return; }
  const rawSource = await fetchRawSource(id);
  const emailText = toEmailText(payload, rawSource);
  chrome.runtime.sendMessage({ type: "CHECK_EMAIL", emailText }, resp => {
    if (resp?.ok) renderBadge(container, resp.result);
    else renderBadge(container, { verdict: "Suspicious", score: 0, reasons: ["Checker offline: " + (resp?.error || "no response")] });
  });
}

new MutationObserver(() => {
  document.querySelectorAll("div.adn").forEach(check);
}).observe(document.body, { childList: true, subtree: true });
