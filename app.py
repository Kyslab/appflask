# sửa sau khi copy
# app.config['MAIL_USERNAME'] = 'mergexceltool'
# app.config['MAIL_PASSWORD'] = 'uhuu dnwi kaiu days'
# app.config['MAIL_DEFAULT_SENDER'] = 'mergexceltool@gmail.com'

# khi dua lên heroku:
# redirect_uri = url_for('authorize_google', _external=True, _scheme='https')

    # client_id='206611615101-g9kp571dagj69qn1b0ffb723c8qn9d7q.apps.googleusercontent.com',
    # client_secret='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',
import secrets
import os
from flask import Flask, request, redirect, url_for, send_file, render_template, flash, session
from werkzeug.utils import secure_filename
import openpyxl
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, SubmitField
from wtforms.validators import InputRequired, Length, Email, ValidationError,EqualTo
from flask_mail import Mail, Message
from random import randint
from urllib.parse import quote as url_quote
from authlib.integrations.flask_client import OAuth
from authlib.integrations.base_client.errors import OAuthError
from itsdangerous import URLSafeTimedSerializer, SignatureExpired


app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PROCESSED_FOLDER'] = 'processed'
app.config['ALLOWED_EXTENSIONS'] = {'xlsx'}

# @app.before_request
# def before_request():
#     if not request.is_secure and not app.debug:
#         url = request.url.replace("http://", "https://", 1)
#         return redirect(url, code=301)
    
# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://u7tbi7nfum7v0:pf5f201f6f9d9fbcc433d951c97a2556850b548a66deed2297b7a41bfe789d0b6@c5p86clmevrg5s.cluster-czrs8kj4isg7.us-east-1.rds.amazonaws.com:5432/d7ctfli13pgsc0'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

# Mail configuration
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = 'mergexceltool'
app.config['MAIL_PASSWORD'] = 'uhuu dnwi kaiu days'
app.config['MAIL_DEFAULT_SENDER'] = 'mergexceltool@gmail.com'

mail = Mail(app)

# OAuth configuration
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id='206611615101-g9kp571dagj69qn1b0ffb723c8qn9d7q.apps.googleusercontent.com',
    client_secret='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',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
if not os.path.exists(app.config['PROCESSED_FOLDER']):
    os.makedirs(app.config['PROCESSED_FOLDER'])

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)
    is_confirmed = db.Column(db.Boolean, default=False)

class RegisterForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(), Length(max=150)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=150)])
    
    def validate_email(self, email):
        user = User.query.filter_by(email=email.data).first()
        if user:
            raise ValidationError('Email is already taken.')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(), Length(max=150)])
    password = PasswordField('Password', validators=[InputRequired(), Length(min=4, max=150)])
    remember = BooleanField('Remember me')
    
class ConfirmEmailForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(), Length(max=150)])
    code = StringField('Confirmation Code', validators=[InputRequired(), Length(min=6, max=6)])

s = URLSafeTimedSerializer(app.config['SECRET_KEY'])
class RequestResetForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email(), Length(max=150)])
    submit = SubmitField('Request Password Reset')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[InputRequired(), Length(min=4, max=150)])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

def send_reset_email(user):
    token = s.dumps(user.email, salt='password-reset-salt')
    msg = Message('Password Reset Request', sender='your-email@gmail.com', recipients=[user.email])
    link = url_for('reset_token', token=token, _external=True)
    msg.body = f'Please click the following link to reset your password: {link}'
    mail.send(msg)

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_request():
    if 'user_id' in session:
        return redirect(url_for('upload_and_list_files'))
    form = RequestResetForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            send_reset_email(user)
        flash('An email has been sent with instructions to reset your password.', 'info')
        return redirect(url_for('login'))
    return render_template('reset_request.html', form=form)

@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    try:
        email = s.loads(token, salt='password-reset-salt', max_age=3600)
    except SignatureExpired:
        flash('The token is expired!', 'danger')
        return redirect(url_for('reset_request'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=email).first()
        if user:
            user.password = form.password.data
            db.session.commit()
            flash('Your password has been updated! You can now log in.', 'success')
            return redirect(url_for('login'))
    return render_template('reset_token.html', form=form)


def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = form.password.data
        new_user = User(email=form.email.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        verification_code = randint(100000, 999999)
        session['email_verification'] = {'email': new_user.email, 'code': verification_code}

        msg = Message('Email Verification', sender='your-email@gmail.com', recipients=[new_user.email])
        msg.body = f'Your verification code is {verification_code}.'
        mail.send(msg)

        flash('Account created successfully. Please check your email for the verification code.', 'success')
        return redirect(url_for('confirm_email', email=new_user.email))
    return render_template('register.html', form=form)

@app.route('/confirm_email', methods=['GET', 'POST'])
def confirm_email():
    if 'email_verification' not in session:
        return redirect(url_for('register'))

    email = session['email_verification']['email']
    form = ConfirmEmailForm(email=email)

    if form.validate_on_submit():
        if form.code.data == str(session['email_verification']['code']):
            user = User.query.filter_by(email=email).first()
            user.is_confirmed = True
            db.session.commit()
            session.pop('email_verification', None)
            flash('Email confirmed successfully. Please log in.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Invalid verification code. Please try again.', 'danger')
    return render_template('confirm_email.html', form=form, email=email)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()

        if len(form.password.data) < 4:
            flash('Password must be at least 4 characters long. Please check your password or log in with Google.', 'danger')
            return render_template('login.html', form=form)
              
        if user and user.password == form.password.data:
            session['user_id'] = user.id
            # flash('Logged in successfully', 'success')
            return redirect(url_for('upload_and_list_files'))
        else:
            flash('Login Unsuccessful. Please check email and password or log in with Google.', 'danger')
    return render_template('login.html', form=form)

@app.route('/login/google')
def login_google():
    nonce = secrets.token_urlsafe()
    session['nonce'] = nonce
    redirect_uri = url_for('authorize_google', _external=True, _scheme='https')
    # redirect_uri = url_for('authorize_google', _external=True, _scheme='http')
    return google.authorize_redirect(redirect_uri, nonce=nonce)
@app.route('/authorize/google')
def authorize_google():
    try:
        token = google.authorize_access_token()
        nonce = session.pop('nonce', None)
        resp = google.parse_id_token(token, nonce=nonce)
        email = resp['email']

        user = User.query.filter_by(email=email).first()
        if not user:
            user = User(email=email, is_confirmed=True)
            db.session.add(user)
            db.session.commit()

        session['user_id'] = user.id
        flash('Logged in successfully with Google.', 'success')
        return redirect(url_for('upload_and_list_files'))
    except OAuthError as e:
        print(e.error)
        flash('Could not authorize with Google. Please try again.', 'danger')
        return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))
@app.route('/privacy') # dùng đăng ksy google search
def privacy():
    return render_template('privacy.html')
@app.route('/google06a54390fa47b952.html') # dùng đăng ksy google search
def google06a54390fa47b952():
    return render_template('google06a54390fa47b952.html')
    # return redirect(url_for('google06a54390fa47b952'))
@app.route('/', methods=['GET', 'POST'])
def upload_and_list_files():
    if 'user_id' not in session:
        flash('Please log in to access this page', 'warning')
        return redirect(url_for('login'))

    if request.method == 'POST':
        if 'files' in request.files:
            files = request.files.getlist('files')
            for file in files:
                if file and allowed_file(file.filename):
                    filename = secure_filename(file.filename)
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(filepath)
            flash('Files uploaded successfully')
        elif 'merge' in request.form:
            remove_empty_rows = 'remove_empty' in request.form
            text_to_remove_list = request.form.getlist('text_to_remove')

            merged_wb = openpyxl.Workbook()
            merged_ws = merged_wb.active
            merged_ws.title = 'Merged Data'

            for filename in os.listdir(app.config['UPLOAD_FOLDER']):
                if allowed_file(filename):
                    filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    wb = openpyxl.load_workbook(filepath, data_only=True)
                    ws = wb.active
                    for row in ws.iter_rows(values_only=True):
                        if remove_empty_rows and all(cell is None for cell in row):
                            continue
                        if any(text in [str(cell) for cell in row if cell is not None] for text in text_to_remove_list):
                            continue
                        merged_ws.append(row)

            merged_filename = 'merged_file.xlsx'
            merged_filepath = os.path.join(app.config['PROCESSED_FOLDER'], merged_filename)
            merged_wb.save(merged_filepath)
            flash('Files merged successfully')
            return redirect(url_for('download_file', filename=merged_filename))

    files = os.listdir(app.config['UPLOAD_FOLDER'])
    files = [f for f in files if allowed_file(f)]
    return render_template('upload_and_list.html', files=files)

@app.route('/delete/<filename>', methods=['POST'])
def delete_file(filename):
    if 'user_id' not in session:
        flash('Please log in to access this page', 'warning')
        return redirect(url_for('login'))

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    if os.path.exists(file_path):
        os.remove(file_path)
        flash(f'File {filename} deleted successfully')
    else:
        flash(f'File {filename} not found')
    return redirect(url_for('upload_and_list_files'))

@app.route('/download/<filename>')
def download_file(filename):
    if 'user_id' not in session:
        flash('Please log in to access this page', 'warning')
        return redirect(url_for('login'))

    file_path = os.path.join(app.config['PROCESSED_FOLDER'], filename)
    if os.path.exists(file_path):
        return send_file(file_path, as_attachment=True)
    else:
        return "File not found", 404

if __name__ == "__main__":
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)
