from .domain_reputation import domain_reputation

def analyze_header(sender, subject):
    score = 0.5
    reasons = []
    
    # Basic email format checks
    if "no-reply" in sender.lower():
        score -= 0.1
        reasons.append("Sender uses no-reply")
    if not sender.endswith((".com", ".org", ".net", ".in")):
        score += 0.2
        reasons.append("Suspicious sender domain")
    if sender.count("@") != 1:
        score += 0.3
        reasons.append("Malformed sender email")
    
    # Domain reputation analysis
    domain_analysis = domain_reputation.comprehensive_domain_analysis(sender)
    domain_score = domain_analysis['trust_score']
    domain_reasons = domain_analysis['reasons']
    
    # Combine scores (70% basic checks, 30% domain reputation)
    final_score = 0.7 * score + 0.3 * domain_score
    all_reasons = reasons + domain_reasons
    
    return min(max(final_score, 0), 1), all_reasons
