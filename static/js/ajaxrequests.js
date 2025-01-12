// Function to send a URL for scanning
function scanUrl() {
    const url = document.getElementById("urlInput").value;
    fetch('/scan', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ url: url })
    })
    .then(response => response.json())
    .then(data => {
        // Display scan result
        document.getElementById("result").innerHTML = `Risk Level: ${data.risk}`;
    })
    .catch(error => console.error('Error:', error));
}

// Function to send a notification
function sendNotification(message) {
    fetch('/notify', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ message: message })
    })
    .then(response => response.json())
    .then(data => {
        console.log("Notification sent");
    })
    .catch(error => console.error('Error:', error));
}

// Example usage: sending a notification
document.getElementById("notifyBtn").addEventListener("click", () => {
    sendNotification("This is a test notification");
});
