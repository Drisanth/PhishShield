// Listen for messages from popup.js
chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (request.action === "extract_email") {
        const emailData = getEmailContent();
        sendResponse(emailData);
    }
    return true; // Keep the message channel open for async
});

// Function to extract email data dynamically
function getEmailContent() {
    let sender = document.querySelector("span[email]")?.innerText || "";
    let subject = document.querySelector("h2.hP")?.innerText || "";
    let body = document.querySelector(".a3s")?.innerText || "";
    let links = [...document.querySelectorAll(".a3s a")].map(a => a.href);

    return { sender, subject, body, links };
}

// Observe Gmail's DOM for dynamic email changes
const observer = new MutationObserver((mutationsList, observer) => {
    mutationsList.forEach((mutation) => {
        // Only act if new nodes added
        if (mutation.addedNodes.length) {
            mutation.addedNodes.forEach((node) => {
                // If email body exists, store it for popup extraction
                if (node.nodeType === 1 && node.querySelector?.(".a3s")) {
                    // Optional: you can store this globally if needed
                }
            });
        }
    });
});

// Start observing Gmail's main container
const gmailContainer = document.querySelector("div[role='main']");
if (gmailContainer) {
    observer.observe(gmailContainer, { childList: true, subtree: true });
}

// Fallback for dynamically loaded Gmail content
document.addEventListener("DOMContentLoaded", () => {
    if (!gmailContainer) {
        const mainContainer = document.querySelector("div[role='main']");
        if (mainContainer) {
            observer.observe(mainContainer, { childList: true, subtree: true });
        }
    }
});
