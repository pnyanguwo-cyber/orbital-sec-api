from flask import Flask, jsonify
from flask_cors import CORS
import requests
import socket

app = Flask(__name__)
CORS(app)

@app.route('/scan/<target>')
def mvp_scan(target):
    try:
        # 1. Get IP and Basic Geo-Data
        geo_req = requests.get(f"http://ip-api.com/json/{target}?fields=status,message,country,city,lat,lon,isp,query")
        geo_data = geo_req.json()

        if geo_data['status'] == 'fail':
            return jsonify({"status": "error", "message": "Target not found"}), 404

        # 2. Use HackerTarget API for a "Pseudo-Nmap" Scan (Free & Legal)
        # This performs a TCP port scan from their infrastructure
        scan_req = requests.get(f"https://api.hackertarget.com/nmap/?q={target}")
        scan_text = scan_req.text

        # Clean up the scan text into a list for our UI
        scan_lines = [line for line in scan_text.split('\n') if "open" in line or "tcp" in line]

        return jsonify({
            "status": "success",
            "ip": geo_data['query'],
            "isp": geo_data['isp'],
            "city": f"{geo_data['city']}, {geo_data['country']}",
            "lat": geo_data['lat'],
            "lon": geo_data['lon'],
            "details": scan_lines[:5] # Limit to top 5 for the UI
        })

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)