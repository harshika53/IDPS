// Connect to the Socket.IO server
const socket = io.connect('http://localhost:5000');

// Listen for real-time notifications
socket.on('notification', function(data) {
    const notificationBox = document.getElementById("notificationBox");
    notificationBox.innerHTML = `New Notification: ${data.message}`;
    notificationBox.style.display = "block"; // Show the notification box
});

// Hide the notification box after a few seconds
setTimeout(() => {
    document.getElementById("notificationBox").style.display = "none";
}, 5000);
