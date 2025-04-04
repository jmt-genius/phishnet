chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
    if (msg.type === "SCAM_ALERT") {
      chrome.notifications.create({
        type: "basic",
        iconUrl: "icons/icon128.png",
        title: "⚠️ Web3 Scam Detected",
        message: msg.message,
        priority: 2
      });
    }
  });
  