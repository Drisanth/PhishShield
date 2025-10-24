from flask import Flask, request, jsonify
from model.phishing_model import analyze_text
from utils.header_analysis import analyze_header
from utils.link_analysis import check_links

app = Flask(__name__)

@app.route('/analyze', methods=['POST'])
def analyze_email():
    data = request.get_json()
    # Header Analysis
    header_score, header_reasons = analyze_header(data.get('sender', ''), data.get('subject', ''))
    # Body Analysis
    body_score, body_keywords = analyze_text(data.get('body', ''))
    # Link Analysis
    link_score, link_reasons = check_links(data.get('links', []))

    # Weighted score
    final_score = round(0.3 * header_score + 0.4 * body_score + 0.3 * link_score, 2)
    if final_score > 0.7:
        verdict = "Phishing 🚨"
    elif final_score > 0.4:
        verdict = "Suspicious ⚠️"
    else:
        verdict = "Safe ✅"

    return jsonify({
        "header_score": header_score,
        "header_reasons": header_reasons,
        "body_score": body_score,
        "body_keywords": body_keywords,
        "link_score": link_score,
        "link_reasons": link_reasons,
        "final_score": final_score,
        "verdict": verdict
    })

if __name__ == '__main__':
    app.run(debug=True)
