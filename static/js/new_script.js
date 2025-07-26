document.addEventListener('DOMContentLoaded', function () {
    // --- Element Selectors ---
    const scanButton = document.getElementById('scan-button');
    const urlInput = document.getElementById('url-input');
    const scanStatusEl = document.getElementById('scan-status');
    const whitelistUl = document.getElementById('whitelist-ul');
    const blacklistUl = document.getElementById('blacklist-ul');
    const notificationList = document.getElementById('notification-list');
    const activityLog = document.getElementById('activity-log-content');
    const toastEl = document.getElementById('toast-notification');
    const navLinks = document.querySelectorAll('.nav-link');
    const views = document.querySelectorAll('.view');
    const mainTitle = document.getElementById('main-title');

    // --- Chart.js Setup ---
    let scanChart;
    let chartData = { safe: 0, unsafe: 0 };
    const chartCtx = document.getElementById('scan-chart').getContext('2d');

    function initializeChart() {
        scanChart = new Chart(chartCtx, {
            type: 'doughnut',
            data: {
                labels: ['Safe URLs', 'Unsafe URLs'],
                datasets: [{
                    label: 'Scan Results',
                    data: [chartData.safe, chartData.unsafe],
                    backgroundColor: ['#28a745', '#dc3545'],
                    borderColor: ['#252831'],
                    borderWidth: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: {
                            color: '#e0e0e0',
                            font: { size: 14 }
                        }
                    }
                },
                cutout: '70%'
            }
        });
    }

    function updateChart(status) {
        if (status === 'safe') chartData.safe++;
        else if (status === 'unsafe') chartData.unsafe++;
        scanChart.data.datasets[0].data = [chartData.safe, chartData.unsafe];
        scanChart.update();
    }

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

    // --- Core API Functions ---
    async function performScan() {
        const url = urlInput.value.trim();
        if (!url) {
            showToast('Please enter a URL.', 'info');
            return;
        }
        scanStatusEl.textContent = 'Scanning...';
        scanStatusEl.className = '';
        logActivity(`Scanning initiated for: ${url}`);

        try {
            const response = await fetch('/passive_scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url: url })
            });
            if (!response.ok) {
                throw new Error(`HTTP error! status: ${response.status}`);
            }
            const result = await response.json();
            updateUI(result);
        } catch (error) {
            console.error('Scan Error:', error);
            scanStatusEl.textContent = 'Scan failed.';
            scanStatusEl.className = 'unsafe';
            showToast('Error during scan.', 'unsafe');
            logActivity(`Scan failed for: ${url}`);
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
        fetchLogs(); // Refresh all logs to show the new entry
        urlInput.value = '';
    }

    async function fetchLists() {
        try {
            const [whitelistRes, blacklistRes] = await Promise.all([
                fetch('/get_whitelist'),
                fetch('/get_blacklist')
            ]);
            const whitelistData = await whitelistRes.json();
            const blacklistData = await blacklistRes.json();
            populateList(whitelistUl, whitelistData.whitelisted_urls);
            populateList(blacklistUl, blacklistData.blacklisted_urls);
        } catch (error) {
            console.error('Error fetching lists:', error);
        }
    }

    function populateList(ulElement, urls) {
        ulElement.innerHTML = '';
        if (!urls || urls.length === 0) {
            ulElement.innerHTML = '<li>No URLs in this list.</li>';
            return;
        }
        urls.forEach(url => {
            const li = document.createElement('li');
            li.textContent = url;
            ulElement.appendChild(li);
        });
    }

    async function fetchLogs() {
        try {
            const response = await fetch('/get_logs');
            if (!response.ok) throw new Error('Failed to fetch logs');
            const logs = await response.json();
            populateLogs(logs);
        } catch (error) {
            console.error('Error fetching logs:', error);
        }
    }

    function populateLogs(logs) {
        activityLog.innerHTML = '';
        if (!logs || logs.length === 0) {
            activityLog.innerHTML = '<p class="log-entry">No activity recorded yet.</p>';
            return;
        }
        logs.forEach(log => {
            const entry = document.createElement('p');
            entry.className = 'log-entry';
            entry.textContent = `[${log.timestamp}] - ${log.url} - [${log.status}]`;
            activityLog.appendChild(entry);
        });
    }
    
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
        notificationList.innerHTML = '';
        if (!notifications || notifications.length === 0) {
            notificationList.innerHTML = '<p class="log-entry">No recent alerts.</p>';
            return;
        }
        notifications.forEach(msg => {
            const entry = document.createElement('p');
            entry.className = 'log-entry alert';
            entry.innerHTML = `🚨 ${msg}`; // Use innerHTML to render emoji
            notificationList.appendChild(entry);
        });
    }

    // This is a temporary, client-side log for immediate feedback
    function logActivity(message) {
        const entry = document.createElement('p');
        entry.className = 'log-entry';
        const timestamp = new Date().toLocaleTimeString();
        entry.textContent = `[${timestamp}] ${message}`;
        // Prepend to show the latest at the top
        if (activityLog.firstChild && activityLog.firstChild.textContent.includes("No activity")) {
            activityLog.innerHTML = '';
        }
        activityLog.prepend(entry);
    }
    
    let toastTimeout;
    function showToast(message, type) {
        clearTimeout(toastTimeout);
        toastEl.textContent = message;
        toastEl.className = `toast show ${type}`;
        toastTimeout = setTimeout(() => {
            toastEl.className = 'toast';
        }, 4000);
    }

    // --- Event Listeners ---
    scanButton.addEventListener('click', performScan);
    urlInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') performScan();
    });

    // --- Initial Data Load ---
    initializeChart();
    fetchLists();
    fetchLogs();
    fetchNotifications();
});