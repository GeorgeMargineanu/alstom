from flask import Flask, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, ValidationError, Email
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
import email_validator

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisismysecret'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=True)
    is_confirmed = db.Column(db.String(150), nullable=True)
    confirmed_on = db.Column(db.DateTime, nullable=True)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Register')
    
    def validate_username(self, username):
        existing_user_username = User.query.filter_by(username=username.data).first()
        print(f"Checking if username '{username.data}' exists...")  # Debug statement
        if existing_user_username:
            print(f"Username '{username.data}' already exists.")  # Debug statement
            raise ValidationError('Username already exists')
        

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/recover_password', methods=['GET', 'POST'])
def recover_password():
    form = RegistrationForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        email = User.query.filter_by(email=form.email.data).first()

        if user or email:
            # Logic for handling password recovery
            # For example, send a recovery email or display a confirmation message
            flash('A recovery email has been sent if the user exists.', 'info')
            return redirect(url_for('login'))

    return render_template('recover.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if 'failed_logins' not in session:  # Initialize if not present
        session['failed_logins'] = 0

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=True)
            session['failed_logins'] = 0
            return redirect(url_for('dashboard'))
        else:
            session['failed_logins'] += 1
            flash('Invalid username or password', 'danger')
            if session['failed_logins'] >= 3:
                flash('You have entered the wrong password 3 times. Please recover your password.', 'danger')
                return redirect(url_for('recover_password'))

    return render_template('login.html', form=form)
@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        try:
            hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
            new_user = User(username=form.username.data, password=hashed_password, email=form.email.data)
            db.session.add(new_user)
            db.session.commit()
            return redirect(url_for('home'))
        except ValidationError as e:
            # Handle the validation error by re-rendering the form with an error message
            form.username.errors.append(str(e))
    return render_template('register.html', form=form)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

