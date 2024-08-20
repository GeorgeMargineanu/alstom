from flask import Flask, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField
from wtforms.validators import DataRequired, ValidationError, Email
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_mail import Mail, Message
import datetime
from itsdangerous import URLSafeTimedSerializer as Serializer

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisismysecret'
db = SQLAlchemy(app)
migrate = Migrate(app, db)
bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

#Config mail server
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = 'georgemargineanu20@gmail.com'
app.config['MAIL_PASSWORD'] = 'dujo jgcj cdjc ulux'
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)


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

    def get_reset_token(self, expires_sec=1800):
        s = Serializer(app.config['SECRET_KEY'], expires_sec)
        return s.dumps({'user_id': self.id})

    @staticmethod
    def verify_reset_token(token):
        s = Serializer(app.config['SECRET_KEY'])
        try:
            user_id = s.loads(token, max_age=1800)['user_id']
        except:
            return None
        return User.query.get(user_id)

class RecoveryForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Recover')

<<<<<<< Updated upstream
=======
class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired()])
    submit = SubmitField('Reset Password')

    def validate_password(self, password):
        if self.password.data != self.confirm_password.data:
            raise ValidationError('Passwords must match.')


>>>>>>> Stashed changes
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
    
    def validate_email(self, email):
        if '@alstom' not in email.data:
            raise ValidationError("You are not authorized to create an account!")
        

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

@app.route('/welcome')
def welcome():
    return render_template('welcome.html')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/recover_password', methods=['GET', 'POST'])
def recover_password():
    form = RecoveryForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            token = user.get_reset_token()
            msg = Message(
                subject='Password Reset Request',
                sender=app.config['MAIL_USERNAME'],
                recipients=[user.email]
            )
            reset_link = url_for('reset_token', token=token, _external=True)
            msg.body = f'''To reset your password, visit the following link:
{reset_link}

If you did not make this request, simply ignore this email and no changes will be made.
'''
            mail.send(msg)
            flash('A password reset email has been sent.', 'info')
            return redirect(url_for('login'))
        else:
            flash('No account found with that email.', 'danger')

    return render_template('recover.html', form=form)


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_token(token):
    user = User.verify_reset_token(token)
    if not user:
        flash('That is an invalid or expired token', 'danger')
        return redirect(url_for('recover_password'))

    form = ResetPasswordForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user.password = hashed_password
        db.session.commit()
        flash('Your password has been updated! You are now able to log in', 'success')
        return redirect(url_for('login'))

    return render_template('reset_token.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if 'failed_logins' not in session:  # Initialize if not present
        session['failed_logins'] = 0

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=True)
            session['failed_logins'] = 0  # Reset failed login counter on success
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
            new_user = User(username=form.username.data, password=hashed_password, email=form.email.data, confirmed_on = datetime.datetime.now())
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

