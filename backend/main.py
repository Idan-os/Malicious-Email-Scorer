import functions_framework
from flask import jsonify, request
import check_mail

@functions_framework.http
def handle_request(request):
    if request.method != 'POST':
        return jsonify({"error": "Method not allowed"}), 405

    request_json = request.get_json(silent=True)
    if not request_json or 'eml' in request_json:
        raw_eml = request_json['eml']
        
        try:
            result = check_mail.analyze_email_risk(raw_eml)
            
            score = result['score']

            if score >= 75:
                verdict = "MALICIOUS"
                reasoning = "High risk indicators found. This email is likely dangerous."
            elif score >= 50:
                verdict = "HIGH SUSPICION"
                reasoning = "Strong signs of phishing or spoofing detected. Proceed with extreme caution."
            elif score >= 25:
                verdict = "SUSPICIOUS"
                reasoning = "Minor inconsistencies detected. Verify the sender before clicking links."
            else:
                verdict = "SAFE"
                reasoning = "No significant threats found. The email appears to be safe."

            return jsonify({
                "score": score,
                "verdict": verdict,
                "alerts": result['alerts'],
                "reasoning": reasoning
            }), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500
            
    return jsonify({"error": "No data"}), 400
