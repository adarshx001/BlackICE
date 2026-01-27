import re
import math

def crack_time_estimate(password):
    charset = 0

    if re.search(r"[a-z]", password):
        charset += 26
    if re.search(r"[A-Z]", password):
        charset += 26
    if re.search(r"[0-9]", password):
        charset += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        charset += 32

    if charset == 0:
        return "Instantly"

    guesses = charset ** len(password)

    # Assume fast offline attack: 1 billion guesses/sec
    seconds = guesses / 1e9

    if seconds < 1:
        return "Instantly"
    elif seconds < 60:
        return "Seconds"
    elif seconds < 3600:
        return "Minutes"
    elif seconds < 86400:
        return "Hours"
    elif seconds < 86400 * 365:
        return "Days"
    else:
        return "Years (offline brute-force)"

def check_password_strength(password):
    score = 0
    reasons = []

    if len(password) >= 8:
        score += 1
    else:
        reasons.append("Too short (minimum 8 characters)")

    if re.search(r"[A-Z]", password):
        score += 1
    else:
        reasons.append("No uppercase letters")

    if re.search(r"[a-z]", password):
        score += 1
    else:
        reasons.append("No lowercase letters")

    if re.search(r"[0-9]", password):
        score += 1
    else:
        reasons.append("No numbers")

    if re.search(r"[^a-zA-Z0-9]", password):
        score += 1
    else:
        reasons.append("No special characters")

    if score <= 2:
        strength = "Weak"
        color = "red"
    elif score <= 4:
        strength = "Medium"
        color = "orange"
    else:
        strength = "Strong"
        color = "green"

    time_to_crack = crack_time_estimate(password)

    return strength, color, time_to_crack, reasons
