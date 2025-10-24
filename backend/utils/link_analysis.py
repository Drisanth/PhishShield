import random

def check_links(links):
    if not links:
        return 0.3, []
    flagged = []
    for link in links:
        if "login" in link or "verify" in link:  # simple pattern check
            flagged.append(f"Suspicious pattern detected in {link}")
    score = round(random.uniform(0.2, 0.9), 2)
    return score, flagged
