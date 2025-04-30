import os
from flask import Flask, redirect, url_for, session, request, render_template, jsonify, make_response
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from dotenv import load_dotenv
from datetime import datetime
import json

# Load environment variables
load_dotenv()

# Initialize Flask app with production settings
app = Flask(__name__, template_folder='templates')
app.secret_key = os.environ.get('SECRET_KEY')

# Critical production configurations
app.config.update(
    SESSION_COOKIE_SECURE=True,     # Only send cookies over HTTPS
    SESSION_COOKIE_HTTPONLY=True,   # Prevent JavaScript access
    SESSION_COOKIE_SAMESITE='Lax',  # CSRF protection
    PERMANENT_SESSION_LIFETIME=86400,  # 1 day session lifetime
    PREFERRED_URL_SCHEME='https'    # Force HTTPS
)

# Flask-Login setup
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id_, email, name):
        self.id = id_
        self.email = email
        self.name = name

# Google OAuth configuration
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'  # Allow different OAuth scopes
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
client_secrets_path = 'client_secret.json'

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_path,
    scopes=[
        'openid',
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/userinfo.profile',
        'https://www.googleapis.com/auth/drive.file'
    ],
    redirect_uri='https://munimaiassistant02t03.onrender.com/callback'
)

@login_manager.user_loader
def load_user(user_id):
    if 'user' in session:
        user_data = session['user']
        return User(user_data['id'], user_data['email'], user_data['name'])
    return None

@app.route('/')
def home():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))
    return render_template('index.html')

@app.route('/login')
def login():
    # Generate anti-forgery state token
    authorization_url, state = flow.authorization_url(
        prompt='consent',
        access_type='offline',
        include_granted_scopes='true'
    )
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    try:
        # Verify state parameter
        if request.args.get('state') != session.get('state'):
            return redirect(url_for('home'))

        # Fetch tokens
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials

        # Get user info
        userinfo_service = build('oauth2', 'v2', credentials=credentials)
        userinfo = userinfo_service.userinfo().get().execute()

        # Create user session
        user = User(
            id_=userinfo['id'],
            email=userinfo['email'],
            name=userinfo.get('name', '')
        )
        login_user(user)

        # Store session data
        session.permanent = True
        session['user'] = {
            'id': userinfo['id'],
            'email': userinfo['email'],
            'name': userinfo.get('name', ''),
            'credentials': {
                'token': credentials.token,
                'refresh_token': credentials.refresh_token,
                'token_uri': credentials.token_uri,
                'client_id': credentials.client_id,
                'scopes': credentials.scopes
            }
        }

        # Create secure response
        response = make_response(redirect(url_for('chat')))
        response.set_cookie(
            'munim_session',
            value=session.sid,
            secure=True,
            httponly=True,
            samesite='Lax',
            max_age=86400
        )
        return response

    except Exception as e:
        print(f"OAuth Error: {str(e)}")
        return redirect(url_for('home'))

@app.route('/chat')
@login_required
def chat():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    return render_template('chat.html', user=session['user'])

@app.route('/api/message', methods=['POST'])
@login_required
def handle_message():
    try:
        user_message = request.json.get('message', '').strip().lower()
        
        # Accounting response logic
        responses = {
            "hello": "Hello! I'm Munim, your accounting assistant. How can I help with invoices, expenses, or reports today?",
            "hi": "Hi there! Ready to manage your finances?",
            "invoice": "To create an invoice, please provide:\n1. Item/service name\n2. Quantity\n3. Price per unit\n\nExample: '2 laptops @ $800 each'",
            "expense": "To record an expense, please specify:\n1. Amount\n2. Category\n3. Description\n\nExample: 'Record $50 for office supplies'",
            "default": "I can help with:\n- Creating invoices\n- Tracking expenses\n- Generating reports\n\nTry asking about any of these!"
        }

        response = responses.get(user_message, responses["default"])
        return jsonify({
            "response": response,
            "timestamp": datetime.now().isoformat(),
            "status": "success"
        })

    except Exception as e:
        return jsonify({
            "response": "Sorry, I encountered an error processing your request.",
            "error": str(e),
            "status": "error"
        }), 500

@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    response = make_response(redirect(url_for('home')))
    response.delete_cookie('munim_session')
    return response

if __name__ == '__main__':
    app.run(ssl_context='adhoc')
