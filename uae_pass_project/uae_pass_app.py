import os
import uuid
import requests
from flask import Flask, redirect, request, session, jsonify
from dotenv import load_dotenv
 
# Load variables from .env
load_dotenv()
 
app = Flask(__name__)
app.secret_key = os.urandom(24)
 
# Load config from .env
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
REDIRECT_URI = os.getenv("REDIRECT_URI")
AUTH_BASE = os.getenv("AUTH_BASE")
 
AUTH_URL = f"{AUTH_BASE}/authorize"
TOKEN_URL = f"{AUTH_BASE}/token"
SCOPE = "urn:uae:digitalid:profile openid"
 
@app.route('/')
def home():
    return '<a href="/login">Login with UAE PASS</a>'
 
@app.route('/login')
def login():
    state = str(uuid.uuid4())
    session['oauth_state'] = state
 
    auth_redirect_url = (
        f"{AUTH_URL}?"
        f"response_type=code&"
        f"client_id={CLIENT_ID}&"
        f"redirect_uri={REDIRECT_URI}&"
        f"scope={SCOPE}&"
        f"state={state}"
    )
    return redirect(auth_redirect_url)
 
@app.route('/callback')
def callback():
    code = request.args.get('code')
    state = request.args.get('state')
 
    if state != session.get('oauth_state'):
        return "Invalid state", 400
 
    token_data = {
        'grant_type': 'authorization_code',
        'code': code,
        'redirect_uri': REDIRECT_URI,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
    }
 
    token_headers = {'Content-Type': 'application/x-www-form-urlencoded'}
    response = requests.post(TOKEN_URL, data=token_data, headers=token_headers)
 
    if response.status_code != 200:
        return f"Token request failed: {response.text}", 400
 
    token_response = response.json()
    id_token = token_response.get("id_token")
 
    # Decode ID Token (demo only)
    payload = id_token.split('.')[1] + '=='
    import base64, json
    decoded = base64.urlsafe_b64decode(payload.encode()).decode()
    user_info = json.loads(decoded)
 
    return jsonify(user_info)
 
if __name__ == '__main__':
    app.run(debug=True)
