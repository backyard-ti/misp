from pymisp import PyMISP, PyMISPError
from flask import Flask, jsonify
import json
import logging
import os

# Flask app setup
app = Flask(__name__)

# Logging configuration
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Load MISP configuration from environment variables for better security
misp_url = os.getenv('MISP_URL', 'https://your_misp_instance_here')
misp_key = os.getenv('MISP_KEY', 'your_api_key_here')
# Convert string to boolean for misp_verifycert
misp_verifycert_str = os.getenv('MISP_VERIFYCERT', 'False')
misp_verifycert = misp_verifycert_str.lower() in ['true', '1', 't']

def init_pymisp(url, key, verifycert):
    try:
        return PyMISP(url, key, verifycert)
    except PyMISPError as e:
        logger.error(f"Could not initialize PyMISP: {e}")
        exit()

def get_events(misp, tag):
    try:
        response = misp.search(tags=tag)
        # Log the number of events fetched for debugging
        if response and 'response' in response:
            logger.info(f"Number of events fetched: {len(response['response'])}")
        else:
            logger.info("No events fetched.")
        return response
    except PyMISPError as e:
        logger.error(f"Error searching events: {e}")
        return None

@app.route('/misp/events/<tag>')
def misp_events(tag):
    misp = init_pymisp(misp_url, misp_key, misp_verifycert)
    events = get_events(misp, tag)
    if events:
        return jsonify(events)
    else:
        return jsonify({"error": "No events found or error fetching events"}), 404

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5001, debug=True)  # Set debug=False for production

