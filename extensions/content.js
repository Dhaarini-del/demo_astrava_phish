// --------------------
// Rule-Based Phishing Detection
// --------------------
function checkUrl(url) {
    let risk = "Safe";
    let reason = "No obvious suspicious patterns";

    if (url.includes('@')) {
        risk = "Suspicious";
        reason = "URL contains '@' symbol";
    } else if (url.match(/(verify|login|update|secure)/i)) {
        risk = "Suspicious";
        reason = "URL contains suspicious keywords";
    } else if (url.match(/\.(xyz|top|club|info)$/)) {
        risk = "Suspicious";
        reason = "URL uses unusual domain extension";
    }

    return { risk, reason };
}

// --------------------
// Domain Age Checker
// --------------------
async function checkDomainAge(url) {
    try {
        let domain = new URL(url).hostname;
        let apiKey = "at_EHrS0Ja7DQSvAWYHhByaY9fDJ4pBP"; // Your API key

        let response = await fetch(
            `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${apiKey}&domainName=${domain}&outputFormat=JSON`
        );

        let data = await response.json();

        let ageDays = data.estimatedDomainAge || null;
        let createdDate = data.WhoisRecord?.createdDateNormalized || "Unknown";

        return { ageDays, createdDate };
    } catch (error) {
        console.log("Domain age check failed:", error);
        return { ageDays: null, createdDate: "Unknown" };
    }
}

// --------------------
// Suspicious URL Heatmap + Tooltip
// --------------------
let safeCount = 0;
let yellowCount = 0;
let redCount = 0;

document.querySelectorAll('a').forEach(link => {
    const url = link.href;
    const data = checkUrl(url);

    // Determine heatmap color
    let color = 'green';
    if (data.risk === 'Suspicious') {
        const issuesCount = 0
            + (url.includes('@') ? 1 : 0)
            + (url.match(/(verify|login|update|secure)/i) ? 1 : 0)
            + (url.match(/\.(xyz|top|club|info)$/) ? 1 : 0);

        if (issuesCount === 1) color = 'yellow';
        else if (issuesCount > 1) color = 'red';
    }

    // Count links for summary
    if (color === 'green') safeCount++;
    else if (color === 'yellow') yellowCount++;
    else redCount++;

    // Apply heatmap styling
    link.style.backgroundColor = color;
    link.style.color = 'white';
    link.style.padding = '2px 4px';
    link.style.borderRadius = '3px';

    // Hover tooltip
    link.addEventListener('mouseover', (e) => {
        let tooltip = document.createElement('div');
        tooltip.className = 'phishing-tooltip';
        tooltip.style.position = 'absolute';
        tooltip.style.backgroundColor = data.risk === 'Safe' ? 'green' : 'red';
        tooltip.style.color = 'white';
        tooltip.style.padding = '5px 10px';
        tooltip.style.borderRadius = '5px';
        tooltip.style.zIndex = '9999';
        tooltip.innerText = `${data.risk}: ${data.reason}`;
        document.body.appendChild(tooltip);
        tooltip.style.left = e.pageX + 10 + 'px';
        tooltip.style.top = e.pageY + 10 + 'px';

        link.addEventListener('mouseout', () => tooltip.remove());
    });
});

// --------------------
// Floating Popup Notification + Ping Sound
// --------------------
window.addEventListener('load', async () => {
    const url = window.location.href;
    const data = checkUrl(url);

    // --------------------
    // Domain Age Check
    // --------------------
    let domainInfo = await checkDomainAge(url);
    let ageWarning = "";
    if (domainInfo.ageDays !== null) {
        if (domainInfo.ageDays < 30) {
            ageWarning = `⚠️ Domain Age: ${domainInfo.ageDays} days (New domain – high phishing risk, created on ${domainInfo.createdDate})`;
        } else {
            ageWarning = `Domain Age: ${domainInfo.ageDays} days (Created on ${domainInfo.createdDate})`;
        }
    } else {
        ageWarning = `⚠️ Domain Age: Unknown`;
    }

    // --------------------
    // Floating Popup Notification for Risky Sites
    // --------------------
    if (data.risk === 'Suspicious') {
        let popup = document.createElement('div');
        popup.id = 'phishing-popup';
        popup.style.position = 'fixed';
        popup.style.top = '20px';
        popup.style.right = '20px';
        popup.style.width = '320px';
        popup.style.backgroundColor = 'red';
        popup.style.color = 'white';
        popup.style.padding = '15px';
        popup.style.borderRadius = '8px';
        popup.style.boxShadow = '0 4px 8px rgba(0,0,0,0.3)';
        popup.style.zIndex = '9999';
        popup.style.fontFamily = 'Arial, sans-serif';
        popup.style.fontSize = '14px';
        popup.style.display = 'flex';
        popup.style.flexDirection = 'column';
        popup.style.gap = '10px';
        popup.innerHTML = `
            <strong>⚠️ Suspicious Site Detected</strong>
            <p>${data.reason}</p>
            <p>${ageWarning}</p>
            <div style="display:flex; justify-content:flex-end; gap:10px;">
                <button id="popup-go-back" style="padding:5px 10px; cursor:pointer;">Go Back</button>
                <button id="popup-dismiss" style="padding:5px 10px; cursor:pointer;">Ignore</button>
            </div>
        `;
        document.body.appendChild(popup);

        // ------------------
        // Play Ping Sound Once User Interacts
        // ------------------
        let audio = new Audio('https://www.myinstants.com/media/sounds/ping.mp3');
        let pingPlayed = false;

        function playPing() {
            if (!pingPlayed) {
                audio.play().catch(err => console.log('Audio blocked:', err));
                pingPlayed = true;
            }
        }

        document.addEventListener('click', playPing);
        document.addEventListener('keydown', playPing);
        document.addEventListener('scroll', playPing);

        // Button actions
        document.getElementById('popup-go-back').onclick = () => window.history.back();
        document.getElementById('popup-dismiss').onclick = () => popup.remove();
    }

    // --------------------
    // Add Summary / Legend
    // --------------------
    let legend = document.createElement('div');
    legend.id = 'phishing-legend';
    legend.style.position = 'fixed';
    legend.style.bottom = '10px';
    legend.style.right = '10px';
    legend.style.backgroundColor = 'rgba(0,0,0,0.7)';
    legend.style.color = 'white';
    legend.style.padding = '10px';
    legend.style.borderRadius = '5px';
    legend.style.fontFamily = 'Arial, sans-serif';
    legend.style.fontSize = '12px';
    legend.style.zIndex = '9999';
    legend.innerHTML = `
        <strong>Link Summary:</strong><br>
        🟢 Safe: ${safeCount} <br>
        🟡 Slightly Suspicious: ${yellowCount} <br>
        🔴 High Risk: ${redCount}
    `;
    document.body.appendChild(legend);
});