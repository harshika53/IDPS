document.addEventListener('DOMContentLoaded', function () {
    // --- Element Selectors ---
    const scanButton = document.getElementById('scan-button');
    const urlInput = document.getElementById('url-input');
    const scanStatusEl = document.getElementById('scan-status');
    const whitelistUl = document.getElementById('whitelist-ul');
    const blacklistUl = document.getElementById('blacklist-ul');
    const activityLog = document.getElementById('activity-log-content');
    const toastEl = document.getElementById('toast-notification');
    const navLinks = document.querySelectorAll('.nav-link');
    const views = document.querySelectorAll('.view');
    const mainTitle = document.getElementById('main-title');

    // --- Navigation Logic ---
    navLinks.forEach(link => {
        link.addEventListener('click', function (e) {
            e.preventDefault();

            // Update active link
            navLinks.forEach(l => l.classList.remove('active'));
            this.classList.add('active');

            const targetId = this.getAttribute('href');
            
            // Update main title
            mainTitle.textContent = this.textContent.replace(this.querySelector('span').textContent, '').trim();

            // Show target view and hide others
            views.forEach(view => {
                if (view.id === targetId.substring(1)) {
                    view.classList.add('active-view');
                } else {
                    view.classList.remove('active-view');
                }
            });
        });
    });

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
                responsive: true, maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom',
                        labels: { color: '#e0e0e0', font: { size: 14 } }
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
            if (!response.ok) throw new Error('Network response was not ok.');
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
        scanStatusEl.className = result.status; // 'safe' or 'unsafe'
        showToast(`URL is ${result.status}. Source: ${result.source}`, result.status);
        logActivity(`Result for ${result.url}: ${result.status} (from ${result.source})`);
        if (result.source === 'scan') updateChart(result.status);
        fetchLists();
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
        if (urls.length === 0) {
            const li = document.createElement('li');
            li.textContent = 'No URLs in this list.';
            ulElement.appendChild(li);
            return;
        }
        urls.forEach(url => {
            const li = document.createElement('li');
            li.textContent = url;
            ulElement.appendChild(li);
});
    }

    function logActivity(message) {
        const entry = document.createElement('p');
        entry.className = 'log-entry';
        const timestamp = new Date().toLocaleTimeString();
        entry.textContent = `[${timestamp}] ${message}`;
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

    // --- Initial Load ---
    initializeChart();
    fetchLists();
});