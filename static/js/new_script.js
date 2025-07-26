document.addEventListener('DOMContentLoaded', function () {
    // --- Element Selectors ---
    const navLinks = document.querySelectorAll('.nav-link');
    const views = document.querySelectorAll('.view');
    const mainTitle = document.getElementById('main-title');
    const scanButton = document.getElementById('scan-button');
    const urlInput = document.getElementById('url-input');
    const scanStatusEl = document.getElementById('scan-status');
    const whitelistUl = document.getElementById('whitelist-ul');
    const blacklistUl = document.getElementById('blacklist-ul');
    const notificationList = document.getElementById('notification-list'); // New element
    const toastEl = document.getElementById('toast-notification');

    // --- Navigation Logic ---
    navLinks.forEach(link => {
        link.addEventListener('click', function (e) {
            e.preventDefault();
            navLinks.forEach(l => l.classList.remove('active'));
            this.classList.add('active');
            const targetId = this.getAttribute('href');
            mainTitle.textContent = this.textContent.replace(this.querySelector('span').textContent, '').trim();
            views.forEach(view => {
                view.classList.toggle('active-view', view.id === targetId.substring(1));
            });
        });
    });

    // --- Chart.js Setup ---
    let scanChart;
    const chartCtx = document.getElementById('scan-chart').getContext('2d');
    function initializeChart() { /* ... same as before ... */ }
    function updateChart(status) { /* ... same as before ... */ }
    initializeChart(); // Call initialization

    // --- Core API Functions ---
    async function performScan() {
        const url = urlInput.value.trim();
        if (!url) {
            showToast('Please enter a URL.', 'info');
            return;
        }
        scanStatusEl.textContent = 'Scanning...';
        try {
            const response = await fetch('/passive_scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });
            if (!response.ok) throw new Error('Network response failed.');
            const result = await response.json();
            updateUI(result);
        } catch (error) {
            console.error('Scan Error:', error);
            scanStatusEl.textContent = 'Scan failed.';
            showToast('Error during scan.', 'unsafe');
        }
    }

    function updateUI(result) {
        scanStatusEl.textContent = result.status;
        scanStatusEl.className = result.status;
        showToast(`URL is ${result.status}. Source: ${result.source}`, result.status);
        if (result.source === 'scan') {
            updateChart(result.status);
            fetchNotifications(); // Refresh notifications after a scan
        }
        fetchLists();
        urlInput.value = '';
    }

    async function fetchLists() { /* ... same as before ... */ }
    function populateList(ulElement, urls) { /* ... same as before ... */ }

    // --- NEW: Function to Fetch and Display Notifications ---
    async function fetchNotifications() {
        try {
            const response = await fetch('/get_notifications');
            if (!response.ok) throw new Error('Failed to fetch notifications');
            const notifications = await response.json();
            populateNotifications(notifications);
        } catch (error) {
            console.error('Error fetching notifications:', error);
        }
    }

    function populateNotifications(notifications) {
        notificationList.innerHTML = ''; // Clear previous notifications
        if (notifications.length === 0) {
            notificationList.innerHTML = '<p class="log-entry">No recent alerts.</p>';
            return;
        }
        notifications.forEach(msg => {
            const entry = document.createElement('p');
            entry.className = 'log-entry alert'; // Add 'alert' class for styling
            entry.textContent = `🚨 ${msg}`;
            notificationList.appendChild(entry);
        });
    }

    // --- Toast Function ---
    let toastTimeout;
    function showToast(message, type) { /* ... same as before ... */ }

    // --- Event Listeners ---
    scanButton.addEventListener('click', performScan);
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') performScan();
    });

    // --- Initial Data Load ---
    fetchLists();
    fetchNotifications(); // <-- Load notifications on startup
});

// Helper functions (can be outside DOMContentLoaded)
function initializeChart() {
    const chartCtx = document.getElementById('scan-chart')?.getContext('2d');
    if (!chartCtx) return;
    this.scanChart = new Chart(chartCtx, {
        type: 'doughnut',
        data: {
            labels: ['Safe URLs', 'Unsafe URLs'],
            datasets: [{ data: [0, 0], backgroundColor: ['#28a745', '#dc3545'], borderWidth: 0 }]
        },
        options: { responsive: true, maintainAspectRatio: false, cutout: '70%', plugins: { legend: { display: false } } }
    });
}
function updateChart(status) {
    if (!this.scanChart) return;
    if (status === 'safe') this.scanChart.data.datasets[0].data[0]++;
    else if (status === 'unsafe') this.scanChart.data.datasets[0].data[1]++;
    this.scanChart.update();
}
// ... other helper functions like showToast, populateList etc.