from flask import Flask, request, jsonify, render_template
from model.phishing_model import analyze_text
from utils.header_analysis import analyze_header
from utils.link_analysis import check_links
from model.feedback_learning import feedback_learner
from model.bert_analyzer import bert_analyzer
from dashboard import scan_dashboard
import json
import os

app = Flask(__name__)

FEEDBACK_FILE = "feedback.json"

def save_feedback(feedback_data):
    """Append feedback to feedback.json"""
    if os.path.exists(FEEDBACK_FILE):
        with open(FEEDBACK_FILE, "r", encoding="utf-8") as f:
            try:
                feedback_list = json.load(f)
            except json.JSONDecodeError:
                feedback_list = []
    else:
        feedback_list = []

    feedback_list.append(feedback_data)
    with open(FEEDBACK_FILE, "w", encoding="utf-8") as f:
        json.dump(feedback_list, f, indent=4, ensure_ascii=False)

@app.route('/analyze', methods=['POST'])
def analyze_email():
    data = request.get_json()

    # Header Analysis (includes domain reputation)
    header_score, header_reasons = analyze_header(data.get('sender', ''), data.get('subject', ''))
    
    # Get detailed domain analysis
    from utils.domain_reputation import domain_reputation
    domain_analysis = domain_reputation.comprehensive_domain_analysis(data.get('sender', ''))

    # Body Analysis (original model)
    body_score, body_keywords = analyze_text(data.get('body', ''))

    # BERT Analysis
    bert_analysis = bert_analyzer.comprehensive_analysis(
        f"{data.get('subject', '')} {data.get('body', '')}"
    )

    # Feedback Learning Analysis
    feedback_score, feedback_reason = feedback_learner.predict_with_feedback_model(
        f"{data.get('subject', '')} {data.get('body', '')}"
    )

    # Link Analysis
    link_score, link_reasons = check_links(data.get('links', []))

    # Enhanced weighted score with BERT and feedback learning
    final_score = round(
        0.2 * header_score + 
        0.25 * body_score + 
        0.2 * bert_analysis['bert_score'] + 
        0.15 * feedback_score + 
        0.2 * link_score, 2
    )
    
    if final_score > 0.8 and final_score <= 1.0:
        verdict = "Phishing 🚨"
    elif final_score < 0.8 and final_score >= 0.5:
        verdict = "Suspicious ⚠️"
    elif final_score < 0.5 and final_score >= 0.0:
        verdict = "Safe ✅"
    else:
        verdict = "Unknown ❓"

    response = {
        "header_score": header_score,
        "header_reasons": header_reasons,
        "domain_analysis": {
            "domain": domain_analysis['domain'],
            "trust_score": domain_analysis['trust_score'],
            "reasons": domain_analysis['reasons'],
            "detailed_analysis": domain_analysis['analysis']
        },
        "body_score": body_score,
        "body_keywords": body_keywords,
        "bert_score": bert_analysis['bert_score'],
        "bert_analysis": {
            "phishing_probability": bert_analysis['phishing_probability'],
            "sentiment_score": bert_analysis['sentiment_score'],
            "intent_score": bert_analysis['intent_score'],
            "pattern_score": bert_analysis['pattern_score']
        },
        "bert_reasons": {
            "phishing": bert_analysis['phishing_reasons'],
            "sentiment": bert_analysis['sentiment_reasons'],
            "intent": bert_analysis['intent_reasons'],
            "patterns": bert_analysis['pattern_reasons']
        },
        "feedback_score": feedback_score,
        "feedback_reason": feedback_reason,
        "link_score": link_score,
        "link_reasons": link_reasons,
        "final_score": final_score,
        "verdict": verdict
    }

    # Add scan to dashboard
    scan_dashboard.add_scan_record(data, response)

    return jsonify(response)


@app.route('/feedback', methods=['POST'])
def feedback():
    """
    Expected JSON:
    {
        "emailData": {sender, subject, body, links},
        "analysisResult": {...},  # same format as /analyze response
        "correct": true/false
    }
    """
    feedback_data = request.get_json()
    if not feedback_data:
        return jsonify({"error": "No feedback data provided"}), 400

    save_feedback(feedback_data)
    
    # Trigger model retraining if we have enough feedback
    feedback_stats = feedback_learner.get_feedback_stats()
    if feedback_stats["total_feedback"] >= 10 and feedback_stats["total_feedback"] % 5 == 0:
        # Retrain model every 5 new feedback entries
        print("Retraining model with new feedback...")
        feedback_learner.train_model()
    
    return jsonify({
        "status": "Feedback saved successfully!",
        "feedback_stats": feedback_stats
    }), 200

@app.route('/feedback/stats', methods=['GET'])
def feedback_stats():
    """Get feedback statistics"""
    stats = feedback_learner.get_feedback_stats()
    return jsonify(stats)

@app.route('/feedback/retrain', methods=['POST'])
def retrain_model():
    """Manually trigger model retraining"""
    success = feedback_learner.train_model()
    if success:
        return jsonify({"status": "Model retrained successfully"}), 200
    else:
        return jsonify({"error": "Not enough data for retraining"}), 400

@app.route('/dashboard')
def dashboard():
    """Serve the dashboard HTML page"""
    return render_template('dashboard.html')

@app.route('/dashboard/stats', methods=['GET'])
def dashboard_stats():
    """Get dashboard statistics"""
    days = request.args.get('days', 7, type=int)
    stats = scan_dashboard.get_dashboard_stats(days)
    return jsonify(stats)

@app.route('/dashboard/export', methods=['GET'])
def export_data():
    """Export scan data"""
    format_type = request.args.get('format', 'json')
    data = scan_dashboard.export_data(format_type)
    
    if format_type == 'json':
        return jsonify(json.loads(data))
    else:
        return data, 200, {'Content-Type': 'text/csv'}


if __name__ == '__main__':
    app.run(debug=True)
