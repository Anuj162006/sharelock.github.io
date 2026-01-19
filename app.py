"""
Flask application entry point for Secure Split-Secret Password Recovery System.
"""

from flask import Flask, send_from_directory
from flask_cors import CORS
import os
from backend.api import api

app = Flask(__name__, static_folder='frontend')
CORS(app)

# Load configuration
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('SESSION_COOKIE_SECURE', 'False').lower() == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = os.environ.get('SESSION_COOKIE_HTTPONLY', 'True').lower() == 'true'

# Register API blueprint
app.register_blueprint(api, url_prefix='/api')

# Serve frontend files
@app.route('/')
def index():
    """Serve the main frontend page."""
    return send_from_directory('frontend', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    """Serve static files from frontend directory."""
    return send_from_directory('frontend', path)


if __name__ == '__main__':
    # Run the application
    app.run(debug=True, host='0.0.0.0', port=5000)


