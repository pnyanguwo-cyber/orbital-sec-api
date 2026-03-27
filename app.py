from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
import requests
import re
import whois  # Ensure you ran 'pip install python-whois'
from datetime import datetime

app = Flask(__name__)
# Enables cross-origin requests so your dashboard can talk to the engine
CORS(app)

# CONFIGURATION
# Your AbuseIPDB Key is hidden here on the server side for security
ABUSE_KEY = 'a28bea8b96e95db1190ff804387c7400b457b2a5934e409a8e36e9bfc620384ecf59d9eaec3ad33b'

# --- IDS ENGINE LOGIC ---
def sentinel_ids_scan(payload):
    """Core logic to scan payloads for attack signatures"""
    signatures = {
        "SQL Injection": {
            "pattern": r"(UNION\s+SELECT|INSERT\s+INTO|DROP\s+TABLE|--|' OR '1'='1')",
            "severity": "CRITICAL"
        },
        "Cross-Site Scripting (XSS)": {
            "pattern": r"(<script>|javascript:|onerror=|alert\(|%3Cscript%3E)",
            "severity": "HIGH"
        },
        "Path Traversal": {
            "pattern": r"(\.\./\.\./|/etc/passwd|/windows/win.ini|%2e%2e%2f)",
            "severity": "HIGH"
        },
        "Remote Command Execution": {
            "pattern": r"(;\s*whoami|;\s*ls|\|\s*cat|&&\s*net\s*user)",
            "severity": "CRITICAL"
        }
    }

    results = []
    for attack, data in signatures.items():
        match = re.search(data["pattern"], payload, re.IGNORECASE)
        if match:
            results.append({
                "type": attack,
                "severity": data["severity"],
                "detected_pattern": match.group()
            })
    return results

# --- FRONTEND ROUTE ---
@app.route('/')
def home():
    """Serves the Orbital Sec Dashboard (must be in /templates folder)"""
    return render_template('index.html')

# --- IDS API ROUTE ---
@app.route('/api/v1/ids/analyze', methods=['POST'])
def analyze_payload():
    """API Endpoint to process IDS requests from the dashboard"""
    data = request.get_json()
    if not data or 'payload' not in data:
        return jsonify({"status": "error", "message": "No payload provided"}), 400
    
    payload = data['payload']
    detections = sentinel_ids_scan(payload)
    
    return jsonify({
        "status": "success",
        "threat_count": len(detections),
        "detections": detections
    })

# --- UPDATED SCAN ROUTE (Matching New HTML) ---
@app.route('/scan/<target>')
def mvp_scan(target):
    """Updated Geo-location, WHOIS, and Port Scan Engine"""
    try:
        # 1. GEOLOCATION DATA (ip-api)
        geo_url = f"http://ip-api.com/json/{target}?fields=status,message,country,city,lat,lon,isp,org,query"
        geo_data = requests.get(geo_url).json()

        if geo_data.get('status') == 'fail':
            return jsonify({"status": "error", "message": "Target not found"}), 404

        # 2. WHOIS DATA (Established & Registrar)
        established_date = "N/A"
        registrar_name = "N/A"
        
        try:
            w = whois.whois(target)
            registrar_name = w.registrar if w.registrar else "N/A"
            
            if w.creation_date:
                creat = w.creation_date
                # Handle cases where creation_date is a list
                dt = creat[0] if isinstance(creat, list) else creat
                established_date = dt.strftime("%Y") 
        except Exception:
            pass # Keep N/A if WHOIS fails

        # 3. PORT SCAN (HackerTarget)
        scan_req = requests.get(f"https://api.hackertarget.com/nmap/?q={target}")
        scan_lines = [line.strip() for line in scan_req.text.split('\n') if "open" in line or "tcp" in line]

        # 4. COMBINED RESPONSE
        return jsonify({
            "status": "success",
            "ip": geo_data.get('query'),
            "isp": geo_data.get('isp'),
            "org": geo_data.get('org', 'N/A'),
            "city": f"{geo_data.get('city')}, {geo_data.get('country')}",
            "lat": geo_data.get('lat'),
            "lon": geo_data.get('lon'),
            "created": established_date,
            "registrar": registrar_name,
            "details": scan_lines[:5]
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# --- PROXY ROUTES ---
@app.route('/proxy/abuse/<ip>')
def proxy_abuse(ip):
    """Fetches Threat Intel from AbuseIPDB safely via Backend"""
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}"
    headers = {
        'Key': ABUSE_KEY,
        'Accept': 'application/json'
    }
    try:
        response = requests.get(url, headers=headers)
        return jsonify(response.json())
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/proxy/whois/<domain>')
def proxy_whois(domain):
    """Fetches Registration Data from RDAP safely via Backend"""
    url = f"https://rdap.org/domain/{domain}"
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return jsonify(response.json())
        else:
            return jsonify({"error": "RDAP record not found"}), response.status_code
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    # host='0.0.0.0' is required for Render/external access
    # Using debug=True for development; change for production
    app.run(host='0.0.0.0', port=5000, debug=True)
