import os
from wtforms.validators import InputRequired, Length, ValidationError, Email
# import email_validator

from flask import Flask, request, redirect, url_for, send_file, render_template, flash, session
from werkzeug.utils import secure_filename
import openpyxl
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Length, ValidationError, Email

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PROCESSED_FOLDER'] = 'processed'
app.config['ALLOWED_EXTENSIONS'] = {'xlsx'}

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://u7tbi7nfum7v0:pf5f201f6f9d9fbcc433d951c97a2556850b548a66deed2297b7a41bfe789d0b6@c5p86clmevrg5s.cluster-czrs8kj4isg7.us-east-1.rds.amazonaws.com:5432/d7ctfli13pgsc0'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])
if not os.path.exists(app.config['PROCESSED_FOLDER']):
    os.makedirs(app.config['PROCESSED_FOLDER'])

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(150), nullable=False)

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
        flash('Account created successfully', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and user.password == form.password.data:
            session['user_id'] = user.id
            flash('Logged in successfully', 'success')
            return redirect(url_for('upload_and_list_files'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

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
