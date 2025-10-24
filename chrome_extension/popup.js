document.getElementById("scanBtn").addEventListener("click", async () => {
  document.getElementById("status").innerText = "Scanning...";

  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    chrome.scripting.executeScript(
      {
        target: { tabId: tabs[0].id },
        function: extractEmailContent
      },
      async (results) => {
        const emailData = results[0].result;

        try {
          const response = await fetch("http://127.0.0.1:5000/analyze", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(emailData)
          });

          const result = await response.json();

          // Show results
          document.getElementById("results").style.display = "block";
          document.getElementById("header-score").innerText = result.header_score + " (" + result.header_reasons.join(", ") + ")";
          document.getElementById("domain-score").innerText = result.domain_analysis.trust_score + " (" + result.domain_analysis.domain + ")";
          document.getElementById("body-score").innerText = result.body_score + " (Keywords: " + result.body_keywords.join(", ") + ")";
          document.getElementById("bert-score").innerText = result.bert_score + " (BERT Analysis)";
          document.getElementById("feedback-score").innerText = result.feedback_score + " (" + result.feedback_reason + ")";
          document.getElementById("link-score").innerText = result.link_score + " (" + result.link_reasons.join(", ") + ")";
          document.getElementById("verdict").innerText = result.verdict;

          document.getElementById("status").style.display = "none";

          // Setup feedback buttons
          setupFeedback(emailData, result);

        } catch (error) {
          document.getElementById("status").innerText = "Error connecting to backend";
          console.error(error);
        }
      }
    );
  });
});

function extractEmailContent() {
  let sender = document.querySelector("span[email]")?.innerText || "";
  let subject = document.querySelector("h2.hP")?.innerText || "";
  let body = document.querySelector(".a3s")?.innerText || "";
  let links = [...document.querySelectorAll(".a3s a")].map(a => a.href);
  return { sender, subject, body, links };
}

// Feedback buttons
function setupFeedback(emailData, analysisResult) {
  const yesBtn = document.getElementById("feedback-yes");
  const noBtn = document.getElementById("feedback-no");

  yesBtn.onclick = () => sendFeedback(emailData, analysisResult, true);
  noBtn.onclick = () => sendFeedback(emailData, analysisResult, false);
}

async function sendFeedback(emailData, analysisResult, isCorrect) {
  try {
    await fetch("http://127.0.0.1:5000/feedback", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ emailData, analysisResult, correct: isCorrect })
    });
    alert("Thanks for your feedback!");
  } catch (error) {
    console.error("Failed to send feedback:", error);
    alert("Could not send feedback. Try again later.");
  }
}
