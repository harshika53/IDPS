// Function to fetch notifications from the server
function getNotifications() {
    fetch('/notifications')
        .then(response => response.json())
        .then(data => {
            if (data.message) {
                const notificationBox = document.getElementById("notificationBox");
                notificationBox.innerHTML = `New Notification: ${data.message}`;
                notificationBox.style.display = "block"; // Show the notification box

                // Hide the notification box after 5 seconds
                setTimeout(() => {
                    notificationBox.style.display = "none";
                }, 5000);  // Hide after 5 seconds
            }
        })
        .catch(err => {
            console.error('Error fetching notifications:', err);
        });
}

// Poll for notifications every 5 seconds
setInterval(getNotifications, 5000);

// Function to display notification
function showNotification(message) {
    const notificationBox = document.getElementById("notificationBox");
    notificationBox.innerHTML = `New Notification: ${message}`;
    notificationBox.style.display = "block";  // Show notification box

    // Hide the notification box after 5 seconds
    setTimeout(() => {
        notificationBox.style.display = "none";
    }, 5000);  // Hide after 5 seconds
}

