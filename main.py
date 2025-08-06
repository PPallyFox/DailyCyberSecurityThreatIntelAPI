import requests
from flask import Flask, jsonify

app = Flask(__name__)

CISA_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

@app.route("/", methods=["GET"])
def get_cisa_advisories():
    try:
        response = requests.get(CISA_FEED, timeout=10)
        response.raise_for_status()
        data = response.json()
        
        advisories = data.get("vulnerabilities", [])[:5]  # get latest 5
        
        summary = [
            {
                "cveID": adv.get("cveID"),
                "vendorProject": adv.get("vendorProject"),
                "product": adv.get("product"),
                "shortDescription": adv.get("shortDescription"),
                "dueDate": adv.get("dueDate")
            }
            for adv in advisories
        ]
        
        return jsonify({"latestAdvisories": summary})
    
    except Exception as e:
        return jsonify({"error": str(e)}), 500
