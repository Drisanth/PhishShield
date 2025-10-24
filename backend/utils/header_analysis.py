def analyze_header(sender, subject):
    score = 0.5
    reasons = []
    if "no-reply" in sender.lower():
        score -= 0.1
        reasons.append("Sender uses no-reply")
    if not sender.endswith((".com", ".org", ".net", ".in")):
        score += 0.2
        reasons.append("Suspicious sender domain")
    if sender.count("@") != 1:
        score += 0.3
        reasons.append("Malformed sender email")
    return min(max(score, 0), 1), reasons
