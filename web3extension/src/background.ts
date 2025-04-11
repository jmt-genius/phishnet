// Listen for navigation events
chrome.webNavigation.onCompleted.addListener((details) => {
  // Only handle main frame navigation (not iframes)
  if (details.frameId === 0) {
    // Inject the popup
    chrome.tabs.sendMessage(details.tabId, { 
      type: 'SHOW_SECURITY_CHECK',
      url: details.url
    });
  }
});

// Listen for keyboard shortcuts
chrome.commands.onCommand.addListener(async (command) => {
  if (command === 'show-security-check') {
    // Get the current active tab
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (tab?.id && tab.url) {
      // Send message to content script to show the popup
      chrome.tabs.sendMessage(tab.id, {
        type: 'SHOW_SECURITY_CHECK',
        url: tab.url
      });
    }
  }
});
