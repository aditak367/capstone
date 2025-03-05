document.addEventListener('DOMContentLoaded', function() {
    chrome.tabs.query({active: true, currentWindow: true}, function(tabs) {
        const currentUrl = tabs[0].url;
        
        // Send message to background script to analyze the page
        chrome.runtime.sendMessage({
            action: "analyzePage",
            url: currentUrl
        }, function(response) {
            displayAnalysis(response);
        });
    });
});

function displayAnalysis(data) {
    const analysisDiv = document.getElementById('analysis');
    analysisDiv.innerHTML = `
        <p>Privacy Score: ${data.privacy_score}/10</p>
        <p>Risk Level: <span class="risk-${data.risk_level.toLowerCase()}">${data.risk_level}</span></p>
        <h3>Detected Trackers:</h3>
        <ul>
            ${data.trackers.map(tracker => `
                <li>${tracker.name} (${tracker.category}) - ${tracker.risk_level}</li>
            `).join('')}
        </ul>
    `;
}
