import os
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from dotenv import load_dotenv
from datetime import datetime

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')  # From Render environment vars

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id_, email, name):
        self.id = id_
        self.email = email
        self.name = name

# Google OAuth setup (CHANGED THIS)
flow = Flow.from_client_secrets_file(
    client_secrets_file='client_secret.json',
    scopes=[
        'openid',
        'https://www.googleapis.com/auth/userinfo.email',
        'https://www.googleapis.com/auth/drive.file'
    ],
    redirect_uri='https://munimaiassistant02t03.onrender.com'  # MUST MATCH Google Cloud
)

# Accounting functions
def handle_accounting_command(message, user_id):
    """Process accounting commands"""
    if "invoice" in message.lower():
        return "Invoice created in your Google Drive"
    elif "expense" in message.lower():
        return "Expense recorded to your ledger"
    else:
        return "I can help with: invoices, expenses, and reports."

# Routes
@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login')
def login():
    authorization_url, state = flow.authorization_url(
        prompt='consent',
        access_type='offline'
    )
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    # Verify state
    if request.args.get('state') != session.get('state'):
        return "State mismatch", 400
    
    # Get tokens
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    
    # Get user info
    userinfo = build('oauth2', 'v2', credentials=credentials).userinfo().get().execute()
    user = User(userinfo['id'], userinfo['email'], userinfo.get('name', ''))
    login_user(user)
    
    # Store in session
    session['user'] = {
        'id': userinfo['id'],
        'email': userinfo['email'],
        'name': userinfo.get('name', ''),
        'credentials': {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token
        }
    }
    
    return redirect(url_for('chat'))

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html', user=session['user'])

@app.route('/api/message', methods=['POST'])
@login_required
def handle_message():
    user_message = request.json.get('message', '')
    response = handle_accounting_command(user_message, session['user']['id'])
    return jsonify({'response': response})

@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('home'))

@login_manager.user_loader
def load_user(user_id):
    if 'user' in session:
        return User(session['user']['id'], session['user']['email'], session['user']['name'])
    return None

if __name__ == '__main__':
    app.run(ssl_context='adhoc')
