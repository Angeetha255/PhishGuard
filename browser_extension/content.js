// content.js
// Scans all links on the page and checks them using the PhishGuard AI backend

const API_URL = "http://localhost:5000/predict";
const REQUEST_DELAY = 200; // Delay between API requests (ms) to avoid overwhelming the server

console.log("🛡️ PhishGuard AI Link Scanner: Script loaded");

function highlightLink(link, prediction, confidence) {
    try {
        if (prediction === "Phishing") {
            link.style.backgroundColor = "#ffcccc";
            link.style.border = "3px solid red";
            link.title = `🔴 Phishing detected! (Confidence: ${confidence}%)`;
        } else if (prediction === "Legitimate") {
            link.style.backgroundColor = "#ccffcc";
            link.style.border = "3px solid green";
            link.title = `✅ Safe link (Confidence: ${confidence}%)`;
        } else {
            link.style.backgroundColor = "#ffffcc";
            link.style.border = "3px solid orange";
            link.title = `❓ Unknown (Confidence: ${confidence}%)`;
        }
        console.log(`✓ Highlighted: ${link.href} => ${prediction}`);
    } catch (e) {
        console.error("Error highlighting link:", e);
    }
}

function checkLink(link, delayMs) {
    const url = link.href;
    if (!url || !url.startsWith("http")) return;

    // Add delay to avoid overwhelming the server
    setTimeout(() => {
        console.log(`→ Checking: ${url}`);
        fetch(API_URL, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: url }),
            mode: 'cors'
        })
        .then(response => {
            if (!response.ok) throw new Error(`HTTP ${response.status}`);
            return response.json();
        })
        .then(data => {
            if (data.prediction) {
                const confidence = Math.round(data.confidence_percentage || 0);
                highlightLink(link, data.prediction, confidence);
            } else {
                console.warn(`No prediction for ${url}:`, data);
            }
        })
        .catch(error => {
            console.error(`✗ Error checking ${url}:`, error.message);
            // Mark as unknown on error
            highlightLink(link, "Unknown", 0);
        });
    }, delayMs);
}

// Scan all links on page load
function scanAllLinks() {
    const links = document.querySelectorAll("a[href]");
    console.log(`📊 Found ${links.length} links on the page`);

    if (links.length === 0) {
        console.warn("No links found on this page");
        return;
    }

    links.forEach((link, index) => {
        // Stagger the requests to avoid overwhelming the server
        checkLink(link, index * REQUEST_DELAY);
    });
}

// Scan on page load
if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", scanAllLinks);
} else {
    scanAllLinks();
}

console.log("✅ PhishGuard AI Link Scanner: Ready");
