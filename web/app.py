import sys
import os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from flask import Flask, render_template
from analyzer.detect_intrusion import detect_brute_force
from analyzer.process_analyzer import analyze_processes
from analyzer.timeline import build_timeline
from analyzer.summary_engine import generate_summary 

app = Flask(__name__, template_folder="../templates", static_folder="../static")

@app.route("/")
def home():
    alerts = detect_brute_force()
    suspicious_processes, mitre_matches = analyze_processes()
    timeline = build_timeline()

    summary = generate_summary(alerts, [], suspicious_processes, mitre_matches)  

    return render_template(
        "dashboard.html",
        alerts=alerts,
        process_logs=suspicious_processes,
        mitre_logs=mitre_matches,
        timeline=timeline,
        summary=summary
    )


if __name__ == "__main__":
    app.run(debug=True)
