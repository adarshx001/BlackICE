import re

def analyze_url(url):
    score = 0
    checks = {}

    # SSL check
    if url.startswith("https://"):
     checks["SSL"] = (True, "Using secure HTTPS protocol")
    else:
        checks["SSL"] = (False, "Uses HTTP (not encrypted)")
        score += 25
        
    # @ symbol check
    if "@" in url:
        checks["Suspicious Chars"] = (False, "Contains '@' symbol")
        score += 25
    else:
        checks["Suspicious Chars"] = (True, "No suspicious characters")

    # Length check
    if len(url) > 75:
        checks["URL Length"] = (False, "URL is unusually long")
        score += 25
    else:
        checks["URL Length"] = (True, "URL length appears normal")

    # IP address check
    if re.search(r"\d{1,3}(\.\d{1,3}){3}", url):
        checks["IP Address"] = (False, "Uses IP address instead of domain")
        score += 25
    else:
        checks["IP Address"] = (True, "Uses a valid domain name")

    # Final assessment
    if score == 0:
        status = "Safe"
        color = "green"
    elif score <= 50:
        status = "Suspicious"
        color = "orange"
    else:
        status = "High Risk"
        color = "red"

    return {
        "status": status,
        "color": color,
        "score": score,
        "checks": checks
    }
