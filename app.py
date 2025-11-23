# app.py

from flask import Flask, render_template_string, request
from modules.port_scanner import scan_ports
from modules.service_detect import detect_services
from modules.os_detect import detect_os
from modules.vuln_checks import run_vuln_checks
from main import parse_ports

app = Flask(__name__)

HTML = """
<!doctype html>
<html>
<head>
<title>Mini-Nessus Scanner</title>
</head>
<body style="font-family: Arial; background:#0b0c10; color:#c5c6c7;">
<h1 style="color:#66fcf1;">Mini-Nessus Web Scanner</h1>

<form method="post">
    <label>Target IP / Domain:</label><br>
    <input name="target" required><br><br>

    <label>Ports (optional):</label><br>
    <input name="ports" placeholder="80,443,8000-8100"><br><br>

    <button type="submit">Scan</button>
</form>

{% if result %}
<hr>
<h2>Result for: {{ result.target }}</h2>

<h3>OS Detection</h3>
<p>OS Guess: {{ result.os_info.os_guess }}</p>
<p>TTL: {{ result.os_info.ttl }}</p>

<h3>Open Ports</h3>
<ul>
{% for p in result.ports %}
    {% if p.state == 'open' %}
        <li>{{ p.port }}/tcp - {{ p.service }}</li>
    {% endif %}
{% endfor %}
</ul>

<h3>Vulnerabilities</h3>
{% if result.vulns %}
<ul>
{% for v in result.vulns %}
    <li><b>[{{ v.severity }}]</b> {{ v.name }} - {{ v.url }}</li>
{% endfor %}
</ul>
{% else %}
<p>No vulnerabilities detected.</p>
{% endif %}
{% endif %}

</body>
</html>
"""

@app.route("/", methods=["GET", "POST"])
def index():
    res = None

    if request.method == "POST":
        target = request.form.get("target")
        ports_raw = request.form.get("ports")

        ports = parse_ports(ports_raw) if ports_raw else None

        port_results = scan_ports(target, ports)
        detect_services(target, port_results)
        os_info = detect_os(target)
        vulns = run_vuln_checks(target, port_results)

        res = {
            "target": target,
            "ports": port_results,
            "os_info": os_info,
            "vulns": vulns
        }

    return render_template_string(HTML, result=res)

if __name__ == "__main__":
    app.run(debug=True)
