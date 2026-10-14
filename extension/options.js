const input = document.getElementById("api");
const ok = document.getElementById("ok");
chrome.storage.sync.get({ api: "http://127.0.0.1:3000/api/analyze" }, ({ api }) => { input.value = api; });
document.getElementById("save").onclick = () => {
  chrome.storage.sync.set({ api: input.value.trim() }, () => { ok.textContent = "Saved ✓"; });
};
