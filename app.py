from flask import Flask, jsonify, render_template
from flask_cors import CORS
import requests

app = Flask(__name__)
# Enables cross-origin requests so your dashboard can talk to the engine
CORS(app)

# CONFIGURATION
# Your AbuseIPDB Key is hidden here on the server side for security
ABUSE_KEY = 'a28bea8b96e95db1190ff804387c7400b457b2a5934e409a8e36e9bfc620384ecf59d9eaec3ad33b'

# --- FRONTEND ROUTE ---
@app.route('/')
def home():
    """Serves the Orbital Sec Dashboard (must be in /templates folder)"""
    return render_template('index.html')

# --- API SCAN ROUTE ---
@app.route('/scan/<target>')
def mvp_scan(target):
    """Main Geo-location and Port Scan Engine"""
    try:
        # 1. Get IP and Basic Geo-Data
        geo_req = requests.get(f"http://ip-api.com/json/{target}?fields=status,message,country,city,lat,lon,isp,query")
        geo_data = geo_req.json()

        if geo_data.get('status') == 'fail':
            return jsonify({"status": "error", "message": "Target not found"}), 404

        # 2. Use HackerTarget API for a "Pseudo-Nmap" Scan
        scan_req = requests.get(f"https://api.hackertarget.com/nmap/?q={target}")
        scan_text = scan_req.text
        scan_lines = [line.strip() for line in scan_text.split('\n') if "open" in line or "tcp" in line]

        return jsonify({
            "status": "success",
            "ip": geo_data.get('query'),
            "isp": geo_data.get('isp'),
            "country": geo_data.get('country'),
            "city": geo_data.get('city'),
            "lat": geo_data.get('lat'),
            "lon": geo_data.get('lon'),
            "details": scan_lines[:5] 
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# --- PROXY ROUTES (To fix CORS errors) ---
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
    # host='0.0.0.0' is required for Render to accept external connections
    app.run(host='0.0.0.0', port=5000)
