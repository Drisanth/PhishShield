# phishing_model.py
import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification
import shap
import warnings
warnings.filterwarnings("ignore")

# =========================
# MODEL INITIALIZATION
# =========================
MODEL_NAME = "distilbert-base-uncased-finetuned-sst-2-english"  # Replace with your phishing-trained model

tokenizer = AutoTokenizer.from_pretrained(MODEL_NAME)
model = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME)
model.eval()

# =========================
# MODEL PREDICTION FUNCTION
# =========================
def model_predict(text_list):
    """
    Predict phishing probability for a batch of texts.
    Returns: list of probabilities (class 1)
    """
    text_list = [str(t) if t is not None else "" for t in text_list]

    inputs = tokenizer(
        text_list,
        return_tensors="pt",
        padding=True,
        truncation=True,
        max_length=256
    )

    with torch.no_grad():
        outputs = model(**inputs)
        probs = torch.nn.functional.softmax(outputs.logits, dim=-1)
        phishing_scores = probs[:, 1].cpu().numpy().tolist()  # class 1 = phishing

    return phishing_scores

# =========================
# SHAP EXPLAINER
# =========================
masker = shap.maskers.Text(tokenizer)
explainer = shap.Explainer(model_predict, masker=masker)

# =========================
# TEXT ANALYSIS FUNCTION
# =========================
def analyze_text(text):
    """
    Analyze email body and return:
    - phishing score (0-1)
    - top 5 suspicious words (SHAP)
    """
    text = str(text) if text is not None else ""
    text = " ".join(text.split()[:250])  # truncate for speed

    # Compute phishing score
    phishing_score = float(model_predict([text])[0])

    # SHAP explainability
    try:
        shap_values = explainer([text], max_evals=50)
        words = shap_values.data[0]
        values = shap_values.values[0]
        word_importance = dict(zip(words, values))

        top_words = sorted(word_importance.items(), key=lambda x: abs(x[1]), reverse=True)[:5]
        top_words_list = [w for w, v in top_words]
    except Exception as e:
        print("SHAP explanation failed:", e)
        top_words_list = ["(explainability skipped)"]

    return round(phishing_score, 2), top_words_list

# =========================
# HEADER ANALYSIS FUNCTION
# =========================
def analyze_headers(headers):
    score = 0
    reasons = []

    from_addr = headers.get("From", "").lower()
    received = headers.get("Received", "")

    if not from_addr or "@" not in from_addr:
        score += 0.3
        reasons.append("Missing or invalid sender address")
    if from_addr and any(x in from_addr for x in ["no-reply@", "support@", "info@"]):
        score += 0.1
    if received and len(received.split()) < 2:
        score += 0.2
        reasons.append("Suspicious 'Received' header pattern")

    return min(score, 1.0), reasons

# =========================
# LINK ANALYSIS FUNCTION
# =========================
def analyze_links(links):
    score = 0
    reasons = []

    for link in links:
        link = link.lower()
        if any(keyword in link for keyword in ["login", "update", "verify", "secure", "account"]):
            score += 0.2
            reasons.append(f"Suspicious keyword in link: {link}")
        if link.count(".") > 3:
            score += 0.2
            reasons.append(f"Too many subdomains: {link}")
        if not link.startswith(("https://", "http://")):
            score += 0.1
            reasons.append(f"Non-standard link: {link}")

    return min(score, 1.0), reasons

# =========================
# TESTING
# =========================
if __name__ == "__main__":
    sample_text = "Your account has been compromised! Click the link immediately to verify your login."
    score, words = analyze_text(sample_text)
    print("Phishing Score:", score)
    print("Top suspicious words:", words)
