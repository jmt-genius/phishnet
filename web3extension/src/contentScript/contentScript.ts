chrome.runtime.sendMessage('I am loading content script', (response) => {
    console.log(response);
    console.log('I am content script')

})
// contentScript.js

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "ANALYSIS_RESULT") {
        console.log("Received analysis result in content script:", message.data);
    }
});

window.onload = (event) => {
    console.log('page is fully loaded');
};
