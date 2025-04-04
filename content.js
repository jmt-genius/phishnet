const suspiciousKeywords = [
    "free airdrop", "connect wallet", "claim now", "get rich quick",
    "send ETH", "urgent", "limited offer", "verify wallet"
  ];
  
  const bodyText = document.body.innerText.toLowerCase();
  
  for (const keyword of suspiciousKeywords) {
    if (bodyText.includes(keyword)) {
      chrome.runtime.sendMessage({
        type: "SCAM_ALERT",
        message: `Possible scam keyword detected: "${keyword}"`
      });
      break;
    }
  }
  