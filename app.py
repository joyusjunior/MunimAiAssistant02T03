import os
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from google.auth.transport import requests
from googleapiclient.discovery import build
import json
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY')

# Flask-Login setup
login_manager = LoginManager()
login_manager.init_app(app)

class User(UserMixin):
    def __init__(self, id_, email, name):
        self.id = id_
        self.email = email
        self.name = name

# Google OAuth setup
GOOGLE_CLIENT_ID = os.environ.get('GOOGLE_CLIENT_ID')
client_secrets_file = "client_secret.json"
flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["openid", "https://www.googleapis.com/auth/userinfo.profile", 
            "https://www.googleapis.com/auth/userinfo.email",
            "https://www.googleapis.com/auth/drive.file"],
    redirect_uri="https://your-app-name.onrender.com/callback"
)

# Accounting functions
def create_invoice(user_data, items):
    invoice = {
        "user": user_data['email'],
        "date": datetime.now().strftime("%Y-%m-%d"),
        "items": items,
        "total": sum(item['price'] * item['quantity'] for item in items)
    }
    return invoice

def add_expense(ledger, amount, category, description):
    entry = {
        "date": datetime.now().strftime("%Y-%m-%d %H:%M"),
        "amount": amount,
        "category": category,
        "description": description
    }
    ledger.append(entry)
    return ledger

# Routes
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login')
def login():
    authorization_url, state = flow.authorization_url()
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    flow.fetch_token(authorization_response=request.url)
    credentials = flow.credentials
    
    userinfo = build('oauth2', 'v2', credentials=credentials).userinfo().get().execute()
    user = User(userinfo['id'], userinfo['email'], userinfo.get('name', ''))
    login_user(user)
    
    session['user'] = {
        'id': userinfo['id'],
        'email': userinfo['email'],
        'name': userinfo.get('name', '')
    }
    session['credentials'] = credentials_to_dict(credentials)
    
    return redirect(url_for('chat'))

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html', user=session['user'])

@app.route('/api/chat', methods=['POST'])
@login_required
def handle_chat():
    message = request.json.get('message', '')
    response = process_accounting_message(message, session['user'])
    return jsonify({"response": response})

def process_accounting_message(message, user):
    # Simple accounting logic - expand this
    if "invoice" in message.lower():
        return "I can help create invoices. Please provide items in format: '2 laptops @ $800 each'"
    elif "expense" in message.lower():
        return "Recorded your expense. Please specify amount and category."
    else:
        return "I'm your accounting assistant. I can help with: invoices, expenses, ledgers, and reports."

if __name__ == '__main__':
    app.run(ssl_context='adhoc')
