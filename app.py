from flask import make_response
from functools import wraps
import os
from flask import Flask, redirect, url_for, session, request, render_template, jsonify, make_response
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from dotenv import load_dotenv
from datetime import datetime

load_dotenv()

app = Flask(__name__, template_folder='templates')
app.secret_key = os.environ.get('SECRET_KEY')
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax'
)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id_, email, name):
        self.id = id_
        self.email = email
        self.name = name

flow = Flow.from_client_secrets_file(
    'client_secret.json',
    scopes=['openid', 'email', 'profile', 'https://www.googleapis.com/auth/drive.file'],
    redirect_uri='https://munimaiassistant02t03.onrender.com/callback'
)

@login_manager.user_loader
def load_user(user_id):
    if 'user' in session:
        return User(session['user']['id'], session['user']['email'], session['user']['name'])
    return None

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login')
def login():
    authorization_url, state = flow.authorization_url(prompt='consent')
    session['state'] = state
    return redirect(authorization_url)
@app.route('/callback')
def callback():
    try:
        # Verify state parameter
        if request.args.get('state') != session.get('state'):
            return "Invalid state parameter", 400
            
        # Fetch tokens
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        
        # Get user info
        userinfo = build('oauth2', 'v2', credentials=credentials).userinfo().get().execute()
        user = User(userinfo['id'], userinfo['email'], userinfo.get('name', ''))
        
        # Proper session setup
        session.permanent = True
        session['user'] = {
            'id': userinfo['id'],
            'email': userinfo['email'],
            'name': userinfo.get('name', ''),
            'credentials': {
                'token': credentials.token,
                'refresh_token': credentials.refresh_token
            }
        }
        
        # Secure cookie response
        resp = make_response(redirect(url_for('chat')))
        resp.set_cookie(
            'session_id', 
            value=session.sid,
            secure=True,
            httponly=True,
            samesite='Lax'
        )
        return resp
        
    except Exception as e:
        print(f"OAuth error: {str(e)}")
        return redirect(url_for('home')
@app.route('/callback')
def callback():
    try:
        # Verify state parameter
        if request.args.get('state') != session.get('state'):
            return "Invalid state parameter", 400
            
        # Fetch tokens
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        
        # Get user info
        userinfo = build('oauth2', 'v2', credentials=credentials).userinfo().get().execute()
        user = User(userinfo['id'], userinfo['email'], userinfo.get('name', ''))
        
        # Proper session setup
        session.permanent = True
        session['user'] = {
            'id': userinfo['id'],
            'email': userinfo['email'],
            'name': userinfo.get('name', ''),
            'credentials': {
                'token': credentials.token,
                'refresh_token': credentials.refresh_token
            }
        }
        
        # Secure cookie response
        resp = make_response(redirect(url_for('chat')))
        resp.set_cookie(
            'session_id', 
            value=session.sid,
            secure=True,
            httponly=True,
            samesite='Lax'
        )
        return resp
        
    except Exception as e:
        print(f"OAuth error: {str(e)}")
        return redirect(url_for('home'))

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html', user=session['user'])

@app.route('/api/message', methods=['POST'])
@login_required
def handle_message():
    user_message = request.json.get('message', '').strip().lower()
    
    responses = {
        "hello": "Hello! I'm Munim, your accounting assistant. I can help with invoices, expenses, and reports.",
        "invoice": "To create an invoice, provide: 1) Item 2) Quantity 3) Price (e.g., '2 laptops @ $800 each')",
        "expense": "To record expenses, provide: 1) Amount 2) Category 3) Description (e.g., '$50 office supplies')",
        "default": "I specialize in: • Invoices • Expenses • Reports • Tax prep. Try: 'Create invoice for 3 laptops'"
    }
    
    response = responses.get(user_message, responses["default"])
    return jsonify({
        "response": response,
        "timestamp": datetime.now().isoformat()
    })

@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(ssl_context='adhoc')
