const recent = new Map();

chrome.webNavigation.onCommitted.addListener(async (details) => {
  if (details.frameId !== 0 || !/^https?:\/\//i.test(details.url)) return;
  // Avoid sending the same top-level URL repeatedly within a short interval.
  const now = Date.now();
  const last = recent.get(details.url) || 0;
  if (now - last < 5000) return;
  recent.set(details.url, now);
  if (recent.size > 200) {
    for (const [url, stamp] of recent) if (now - stamp > 60000) recent.delete(url);
  }
  let title = "";
  try {
    const tab = await chrome.tabs.get(details.tabId);
    title = tab.title || "";
  } catch (_) {}
  try {
    await fetch("http://127.0.0.1:5000/api/websites/visit", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: details.url, title, source: "Chrome/Edge extension" })
    });
  } catch (_) {
    // SentinelDF may be stopped. The next navigation will retry.
  }
});
