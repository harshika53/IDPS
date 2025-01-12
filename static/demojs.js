// Functionality for Quick Scan Button
document.getElementById('quick-scan').addEventListener('click', function() {
    const url = prompt("Enter URL to scan:");
    if (url) {
        alert(`Scanning ${url}...`);
        document.getElementById('scan-status').textContent = "Scanning...";

        // Simulate URL scanning and check for unsafe conditions
        setTimeout(() => {
            const isSafe = checkIfSafe(url);
            if (isSafe) {
                document.getElementById('scan-status').textContent = "Safe"; // Safe URL
                addAlert(`URL scanned: ${url} - Safe`);
            } else {
                document.getElementById('scan-status').textContent = "Unsafe"; // Unsafe URL
                addAlert(`URL scanned: ${url} - Unsafe`);
            }
        }, 2000);
    }
});

// Function to check if the URL is safe (more improved logic)
function checkIfSafe(url) {
    // Define common unsafe domains and patterns
    const unsafePatterns = [
        /phishing/, /malware/, /fake/, /scam/, /virus/,
        /http:\/\/|https:\/\/.*\.ru$/, // URLs with Russian domain extensions are commonly associated with phishing
        /http:\/\/|https:\/\/.*\.top$/, // .top domains often used for scammy sites
        /http:\/\/|https:\/\/.*\.xyz$/  // .xyz domains also have a bad reputation for scams
    ];

    // Check if the URL matches any of the unsafe patterns
    for (let pattern of unsafePatterns) {
        if (pattern.test(url.toLowerCase())) {
            return false; // Unsafe URL
        }
    }

    // For further improvement: Check if the URL is in a blacklist (e.g., using a service like Google Safe Browsing)
    return true; // Safe URL (for now, as no unsafe patterns were matched)
}

// Functionality for Whitelist and Blacklist Buttons
document.getElementById('whitelist-url').addEventListener('click', function() {
    alert("URL added to Whitelist");
    addAlert("URL added to Whitelist");
});

document.getElementById('blacklist-url').addEventListener('click', function() {
    alert("URL added to Blacklist");
    addAlert("URL added to Blacklist");
});

// Functionality for View Activity Logs Button
document.getElementById('view-activity-logs').addEventListener('click', function() {
    alert("Displaying activity logs...");
    // In production, fetch logs from the backend
});

// Function to add alerts to Notifications section
function addAlert(message) {
    const alertContainer = document.getElementById('alerts');
    const alert = document.createElement('div');
    alert.className = 'alert-item';
    alert.textContent = message;
    alertContainer.appendChild(alert);
    setTimeout(() => {
        alertContainer.removeChild(alert);
    }, 5000);
}

// Function to fetch and display a CSV file for the whitelist
document.getElementById('view-whitelist-file').addEventListener('click', function () {
    fetch('/view_csv/whitelist.csv') // Fetch from Flask route
        .then((response) => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.text(); // Parse the response as text (CSV data)
        })
        .then((data) => {
            displayCSVContent(data, 'Whitelist URLs');
        })
        /*.catch((error) => {
            console.error('There was a problem with the fetch operation:', error);
            alert('Failed to load the whitelist file.');
        });*/
});

// Function to fetch and display a CSV file for the blacklist
document.getElementById('view-blacklist-file').addEventListener('click', function () {
    fetch('/view_csv/blacklist.csv') // Fetch from Flask route
        .then((response) => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.text(); // Parse the response as text (CSV data)
        })
        .then((data) => {
            displayCSVContent(data, 'Blacklist URLs');
        })
        /*.catch((error) => {
            console.error('There was a problem with the fetch operation:', error);
            alert('Failed to load the blacklist file.');
        });*/
});


// Function to display CSV content
function displayCSVContent(data, title) {
    const contentDiv = document.getElementById('csv-content');
    const rows = data.split('\n').map((row) => row.split(',')); // Parse CSV into rows and columns
    let html = `<h3>${title}</h3><table class="csv-table"><thead><tr>`;
    rows[0].forEach((header) => (html += `<th>${header}</th>`)); // Table headers
    html += `</tr></thead><tbody>`;
    rows.slice(1).forEach((row) => {
        html += `<tr>${row.map((cell) => `<td>${cell}</td>`).join('')}</tr>`;
    });
    html += `</tbody></table>`;
    contentDiv.innerHTML = html;
}

// FAQ toggle functionality
document.querySelector('.faq-header').addEventListener('click', function() {
    const faqContent = document.getElementById('faq-content');
    const toggleArrow = document.getElementById('toggle-faq-arrow');
    
    // Toggle visibility of FAQ content
    faqContent.classList.toggle('hidden-content');
    
    // Toggle the rotation of the arrow
    toggleArrow.classList.toggle('open');
});

