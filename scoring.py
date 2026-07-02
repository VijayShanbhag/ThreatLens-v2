def calculate_score(alerts):

    score = 0

    for alert in alerts:

        if alert["severity"] == "HIGH":

            score += 20

        elif alert["severity"] == "MEDIUM":

            score += 10

        else:

            score += 3

    return min(score, 100)


def get_risk_level(score):

    if score >= 70:

        return "HIGH"

    elif score >= 40:

        return "MEDIUM"

    return "LOW"