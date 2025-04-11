
// Listen for the message from contractanalyser script
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.type === "analysis_completed") {
        const analysisData = message.data;
        openAnalysisDialog(analysisData);
    }
});

// Function to open dialog with analysis data
function openAnalysisDialog(analysisData) {
    document.body.innerHTML += `
      <dialog>
        <h3>Warning: Contract Analysis Completed</h3>
        <p><strong>Vulnerabilities Found:</strong> ${analysisData.vulnerabilities}</p>
        <p><strong>Risk Level:</strong> ${analysisData.riskLevel}</p>
        <br>
        <button>Continue</button>
      </dialog>
    `;

    var dialog = document.querySelector("dialog");

    // Add event listener to close the dialog when "Continue" is clicked
    dialog.querySelector("button").addEventListener("click", function() {
        dialog.close();
    });

    // Display the dialog
    dialog.showModal();
}

