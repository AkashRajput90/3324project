from flask import Flask, render_template, redirect, send_from_directory, url_for, request, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, validators
from passlib.hash import sha256_crypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Replace this with a database in a production environment
users = {}
@app.route('/')
def landing():
    return render_template('landing.html')

class SignupForm(FlaskForm):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [
        validators.DataRequired(),
        validators.EqualTo('confirm', message='Passwords must match')
    ])
    confirm = PasswordField('Confirm Password')
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    username = StringField('Username', [validators.DataRequired()])
    password = PasswordField('Password', [validators.DataRequired()])
    submit = SubmitField('Log In')

@app.route('/')
def index():
    return redirect(url_for('login'))

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = SignupForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password = sha256_crypt.encrypt(str(form.password.data))  # Hash the password
        if username in users:
            flash('Username already exists. Please choose another.', 'danger')
        else:
            users[username] = {'username': username, 'password': password}
            flash('You are now registered and can log in.', 'success')
            return redirect(url_for('login'))
    return render_template('signup.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm(request.form)
    if request.method == 'POST' and form.validate():
        username = form.username.data
        password_candidate = form.password.data
        if username in users:
            stored_password = users[username]['password']
            if sha256_crypt.verify(password_candidate, stored_password):
                flash('You are now logged in.', 'success')
                return redirect(url_for('dashboard'))
            else:
                flash('Invalid password.', 'danger')
        else:
            flash('Username not found.', 'danger')
    return render_template('login.html', form=form)

@app.route('/dashboard')
def dashboard():
    return render_template('dashboard.html')

if __name__ == '__main__':
    app.run(debug=True)