from flask import Flask, render_template, redirect, url_for, session, flash
from flask_sqlalchemy import SQLAlchemy
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, EmailField, TextAreaField, RadioField, FormField
from wtforms.validators import DataRequired, ValidationError, Email, EqualTo
from flask_login import UserMixin, login_user, LoginManager, login_required, current_user, logout_user
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate
from flask_mail import Mail, Message
from wtforms.fields import FieldList
import datetime
import jwt
from itsdangerous import URLSafeTimedSerializer as Serializer
from flask_wtf.csrf import CSRFProtect

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
#app.config['WTF_CSRF_ENABLED'] = False #disable CSRF only for debug purposes
csrf = CSRFProtect(app)  # Add this line to set up CSRF protection
mail = Mail(app)

@login_manager.user_loader
def load_user(user_id):
    return db.session.get(User, int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(150), nullable=False)
    email = db.Column(db.String(150), unique=True, nullable=True)
    is_confirmed = db.Column(db.String(150), nullable=True)
    confirmed_on = db.Column(db.DateTime, nullable=True)
    user_type = db.Column(db.String(150), nullable=False)

    def get_reset_token(self, expires_seconds=1800):
        token = jwt.encode(
            {'reset_password': self.id, 'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=expires_seconds)},
            app.config['SECRET_KEY'],
            algorithm='HS256'
        )
        return token

    @staticmethod
    def verify_reset_token(token):
        try:
            user_id = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])['reset_password']
        except:
            return None
        return User.query.get(user_id)
    
class UserAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(250), nullable=False)
    answer = db.Column(db.String(250), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class AdditionalText(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(500), nullable=False)  # Adjust size as needed
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class QuestionForm(FlaskForm):
    answer = RadioField('', choices=[
        ('😊', 'Happy'),    # Smiley Face
        ('😐', 'Neutral'),  # Neutral Face
        ('😞', 'Sad')       # Sad Face
    ], validators=[DataRequired()])

class MultiQuestionForm(FlaskForm):
    questions = FieldList(FormField(QuestionForm), min_entries=5)  # Adjust min_entries as needed
    additional_text = TextAreaField('Additional Comments', validators=[DataRequired()])  # Ensure this field is present
    submit = SubmitField('Submit All')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

class RecoveryForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired(), Email()])
    submit = SubmitField('Recover')

class ResetPasswordForm(FlaskForm):
    password = PasswordField('New Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Reset Password')

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

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    return render_template('dashboard.html')

class MessageForm(FlaskForm):
    contents = FieldList(TextAreaField('Message', validators=[DataRequired()]), min_entries=3)  # Example of multiple text areas
    submit = SubmitField('Send')

@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

@app.route('/message_sent')
@login_required
def some_view():
    return render_template('message_sent.html')

questions_list = [
    "Project tasks are followed in the weekly report?",
    "Additional tasks are followed in the weekly report?",
    "Do you think we are at least at 75% of the milestone proposed related to the 'mirror of our activity'?",
    "Is it useful for you to have completed data in the weekly report?",
    "Do you think that what was agreed upon till now in the team was respected?",
]

@app.route('/questions', methods=['GET', 'POST'])
@login_required
def questions():
    form = MultiQuestionForm()

    if form.validate_on_submit():
        for i, question_form in enumerate(form.questions):
            selected_answer = question_form.answer.data
            if selected_answer:
                user_answer = UserAnswer(
                    question=questions_list[i],
                    answer=selected_answer,
                    user_id=current_user.id
                )
                db.session.add(user_answer)

        additional_message = form.additional_text.data 
        if additional_message:
            additional_text_entry = AdditionalText(
                message=additional_message,
                user_id=current_user.id
            )
            db.session.add(additional_text_entry)

        try:
            db.session.commit()
            #flash('Your answers have been submitted!', 'success')
        except Exception as e:
            print(f"Error committing to the database: {e}")

        return redirect(url_for('statistics'))

    return render_template('questions.html', form=form, questions=questions_list)

@app.route('/statistics', methods=['GET'])
@login_required
def statistics():
    all_answers = UserAnswer.query.all()
    #all_additional_texts = AdditionalText.query.filter_by(user_id=current_user.id).all()  # this displays only the messages written by the user
    all_additional_texts = AdditionalText.query.all() #This retrieves all the messages

    statistics = {
        'total': len(all_answers),
        'question_stats': {}
    }
 
    # Define emoji mappings
    emoji_mapping = {
        '😊': 'happy',
        '😐': 'neutral',
        '😞': 'sad'
    }
 
    # Process answers for each question
    for question in questions_list:
        question_answers = [answer for answer in all_answers if answer.question == question]
       
        # Count responses based on emojis
        counts = {
            'happy': sum(1 for a in question_answers if a.answer == '😊'),
            'neutral': sum(1 for a in question_answers if a.answer == '😐'),
            'sad': sum(1 for a in question_answers if a.answer == '😞'),
        }
 
        statistics['question_stats'][question] = counts

    return render_template('statistics.html', statistics=statistics, additional_texts=all_additional_texts)

@app.route('/messages', methods=['GET'])
@login_required
def messages():
    # Query all additional messages from the current user
    all_additional_texts = AdditionalText.query.filter_by(user_id=current_user.id).all()
    return render_template('messages.html', additional_texts=all_additional_texts)

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
            return redirect(url_for('questions'))
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
            new_user = User(username=form.username.data, password=hashed_password, email=form.email.data, confirmed_on = datetime.datetime.now(), user_type = 'user')
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

