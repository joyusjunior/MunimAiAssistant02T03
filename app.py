import os
from flask import Flask, redirect, url_for, session, request, render_template, jsonify, make_response
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from google_auth_oauthlib.flow import Flow
from googleapiclient.discovery import build
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, template_folder='templates')
app.secret_key = os.environ.get('SECRET_KEY')

# Critical production settings
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=86400  # 1 day
)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id_, email, name):
        self.id = id_
        self.email = email
        self.name = name

# Google OAuth setup
os.environ['OAUTHLIB_RELAX_TOKEN_SCOPE'] = '1'
flow = Flow.from_client_secrets_file(
    'client_secret.json',
    scopes=['openid', 'email', 'profile', 'https://www.googleapis.com/auth/drive.file'],
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
    authorization_url, state = flow.authorization_url(
        prompt='consent',
        access_type='offline'
    )
    session['state'] = state
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    try:
        if request.args.get('state') != session.get('state'):
            return "Invalid state", 400
            
        flow.fetch_token(authorization_response=request.url)
        credentials = flow.credentials
        
        userinfo = build('oauth2', 'v2', credentials=credentials).userinfo().get().execute()
        user = User(userinfo['id'], userinfo['email'], userinfo.get('name', ''))
        login_user(user)
        
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
        
        resp = make_response(redirect(url_for('chat')))
        resp.set_cookie('session_id', value=session.sid, secure=True, httponly=True, samesite='Lax')
        return resp
        
    except Exception as e:
        print(f"OAuth error: {str(e)}")
        return redirect(url_for('home'))

@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html', user=session['user'])

@app.route('/logout')
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(ssl_context='adhoc')
