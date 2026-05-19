// popup.js
const API_URL = "http://localhost:5000/predict";

const urlInput = document.getElementById("urlInput");
const checkBtn = document.getElementById("checkBtn");
const testBtn = document.getElementById("testBtn");
const resultDiv = document.getElementById("result");
const statusDiv = document.getElementById("status");

function showResult(message, color) {
    resultDiv.textContent = message;
    resultDiv.style.color = color;
    resultDiv.classList.add("show");
}

function testAPI() {
    testBtn.disabled = true;
    testBtn.textContent = "Testing...";
    statusDiv.textContent = "Testing backend connection...";

    fetch(API_URL, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: "https://google.com" }),
        mode: 'cors'
    })
    .then(response => {
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
    })
    .then(data => {
        testBtn.textContent = "Test API";
        testBtn.disabled = false;
        statusDiv.textContent = "✅ Backend is running and responding!";
        console.log("API Test Response:", data);
    })
    .catch(error => {
        testBtn.textContent = "Test API";
        testBtn.disabled = false;
        statusDiv.textContent = `❌ Backend error: ${error.message}. Make sure it's running on localhost:5000`;
        console.error("API Test Failed:", error);
    });
}

function checkURL() {
    const url = urlInput.value.trim();
    const resultDiv = document.getElementById("result");
    
    if (!url) {
        showResult("❌ Please enter a URL", "red");
        return;
    }
    
    if (!url.startsWith("http://") && !url.startsWith("https://")) {
        showResult("❌ URL must start with http:// or https://", "red");
        return;
    }
    
    checkBtn.disabled = true;
    checkBtn.textContent = "Checking...";
    showResult("⏳ Checking...", "blue");
    
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
        checkBtn.disabled = false;
        checkBtn.textContent = "Check";
        
        const prediction = data.prediction || "Unknown";
        const confidence = Math.round(data.confidence_percentage || 0);
        const method = data.detection_method || "unknown";
        
        let message = "";
        let color = "gray";
        
        if (prediction === "Phishing") {
            message = `🔴 PHISHING DETECTED!\n\nConfidence: ${confidence}%\nMethod: ${method}\n\nWarning: This URL appears to be malicious!`;
            color = "red";
        } else if (prediction === "Legitimate") {
            message = `✅ SAFE LINK\n\nConfidence: ${confidence}%\nMethod: ${method}\n\nThis URL appears to be legitimate.`;
            color = "green";
        } else {
            message = `⚠️ UNKNOWN/SUSPICIOUS\n\nConfidence: ${confidence}%\nMethod: ${method}\n\nUnable to determine if this URL is safe.`;
            color = "orange";
        }
        
        showResult(message, color);
    })
    .catch(error => {
        checkBtn.disabled = false;
        checkBtn.textContent = "Check";
        showResult(`❌ Error: ${error.message}\n\nMake sure backend is running:\ncd backend && python app.py`, "red");
        console.error("Check failed:", error);
    });
}

checkBtn.addEventListener("click", checkURL);
testBtn.addEventListener("click", testAPI);

urlInput.addEventListener("keypress", (e) => {
    if (e.key === "Enter") checkURL();
});

// Show status on load
statusDiv.textContent = "Click 'Test API' to verify backend connection";

