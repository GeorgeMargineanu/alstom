from flask import Flask, render_template, redirect, url_for, session, flash, request
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
import pandas as pd
from flask import send_file, abort
import io
from wtforms import HiddenField


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
app.config['WTF_CSRF_ENABLED'] = False #disable CSRF only for debug purposes
csrf = CSRFProtect(app)  # Add this line to set up CSRF protection# 
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
            {'reset_password': self.id, 'exp': datetime.utcfromtimestamp() + datetime.timedelta(seconds=expires_seconds)},
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
    
class Question(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.String(255),  nullable=False)
    
    def __repr__(self):
        return f'<Question {self.text}>'
    
class UserAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question = db.Column(db.String(250), nullable=False)
    answer = db.Column(db.String(250), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class AdditionalText(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.String(500), nullable=False)  # Adjust size as needed
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref='messages')

"""
 '1': 'Very Poor',
        '2': 'Poor',
        '3': 'Fair',
        '4': 'Below average',
        '5': 'Average',
        '6': 'Good',
        '7': 'Very Good',
        '8': 'Excellent',
        '9': 'Exceptional',
        '10': 'Perfect'
        """

class QuestionForm(FlaskForm):
    answer = RadioField('', choices=[
        ('1', 'Very Poor'),    # Smiley Face
        ('2', 'Poor'),  # Neutral Face
        ('3', 'Fair'),
        ('4', 'Below average'),
        ('5', 'Average'),
        ('6', 'Good'),
        ('7', 'Very Good'),
        ('8', 'Excellent'),
        ('9', 'Exceptional'),
        ('10', 'Perfect'),      # Sad Face
    ], validators=[DataRequired()])


class MultiQuestionForm(FlaskForm):
    questions = FieldList(FormField(QuestionForm), min_entries=5)  # Adjust min_entries as needed
    additional_text = TextAreaField('Additional Comments', validators=[DataRequired()])  # Ensure this field is present
    submit = SubmitField('Submit All')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@app.route('/admin/download_statistics', methods=['GET'])
@login_required
def download_statistics():
    if current_user.user_type != 'Admin':
        flash('You do not have permission to perform this action', 'error')
        return redirect(url_for('statistics'))

    # Fetch the data needed for the Excel file
    all_answers = UserAnswer.query.all()
    all_users = {user.id: user.username for user in User.query.all()}

    statistics = {}
    vote_sums = {}
    vote_counts = {}

    # Process the answers to calculate votes and averages
    for answer in all_answers:
        question = answer.question
        username = all_users.get(answer.user_id, 'Unknown')
        vote = answer.answer
        
        if question not in statistics:
            statistics[question] = {user: 'No Vote' for user in all_users.values()}
            vote_sums[question] = 0
            vote_counts[question] = 0
        
        # Update the vote for the specific user
        statistics[question][username] = vote

        # Convert vote to numeric if possible for averaging
        try:
            numeric_vote = float(vote)
            vote_sums[question] += numeric_vote
            vote_counts[question] += 1
        except ValueError:
            pass

    # Calculate average votes for each question
    averages = {}
    for question, total in vote_sums.items():
        count = vote_counts[question]
        averages[question] = "{:.2f}".format(total / count) if count > 0 else 'No Votes'

    # Create a pandas DataFrame to hold the data
    # First column: Question, Second column: Average, followed by user votes
    data = []
    for question, votes in statistics.items():
        row = [question, averages[question]]  # First two columns: Question and Average
        row.extend(votes[user] for user in all_users.values())  # Append user votes
        data.append(row)

    # Create column headers
    columns = ['Question', 'Average'] + [username for username in all_users.values()]

    # Convert to DataFrame
    df = pd.DataFrame(data, columns=columns)

    # Save DataFrame to Excel
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Statistics')

    output.seek(0)  # Move the pointer to the beginning of the stream

    # Send the file to the user for download
    return send_file(output, as_attachment=True, download_name="statistics.xlsx", mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

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

class AddQuestionForm(FlaskForm):
    question = StringField('Question', validators=[DataRequired()])
    submit = SubmitField('Add Question')

@app.route('/admin/add_question', methods=['GET', 'POST'])
@login_required
def add_question():
    if current_user.user_type != 'Admin':
        return redirect(url_for('questions'))

    form = AddQuestionForm()

    if form.validate_on_submit():
        new_question = Question(text=form.question.data)  # Now we use the new field
        db.session.add(new_question)

        try:
            db.session.commit()
            return redirect(url_for('questions'))  # Redirect to the questions page
        except Exception as e:
            print(f"Error committing to the database: {e}")

    return render_template('add_question.html', form=form)

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

@app.route('/already_voted')
@login_required
def already_voted():
    return render_template('already_voted.html')

@app.route('/questions', methods=['GET', 'POST'])
@login_required
def questions():
    print("Request method:", request.method)
    form = MultiQuestionForm()
    form.questions.entries.clear()
    questions_list = Question.query.all()  # Retrieve questions from the database
    print(type(form), 'type form')
    print(questions_list, 'questions list')

    # Step 1: Check if the user has already voted
    has_voted = UserAnswer.query.filter_by(user_id=current_user.id).first()

    if has_voted:
        # User has already voted, redirect to another page or show a message
        return redirect(url_for('already_voted'))  # Redirect to a page that indicates they've already voted

    if form.validate_on_submit():
        for i in range(len(questions_list)):
            selected_answer = request.form.get(f'questions-{i + 1}-answer')
            print('Selected answer:', selected_answer)
            if selected_answer:
                user_answer = UserAnswer(
                    question=questions_list[i].text,
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
            return redirect(url_for('statistics'))  # Redirect to statistics page after submission
        except Exception as e:
            print(f"Error committing to the database: {e}")
    
    print(form.errors)  # Log form errors if exist
    return render_template('questions.html', form=form, questions=questions_list)

@app.route('/admin/statistics', methods=['GET'])
@login_required
def admin_statistics():
    if current_user.user_type != 'Admin':
        return redirect(url_for('statistics'))
    
    all_answers = UserAnswer.query.all()
    all_users = {user.id: user.username for user in User.query.all()}
    
    # Reorganize statistics for unique questions
    statistics = {}
    vote_sums = {}
    vote_counts = {}
    
    for answer in all_answers:
        question = answer.question
        username = all_users.get(answer.user_id, 'Unknown')
        vote = answer.answer
        
        if question not in statistics:
            statistics[question] = {user: 'No Vote' for user in all_users.values()}  # Initialize with no votes
            vote_sums[question] = 0  # Sum of votes for average calculation
            vote_counts[question] = 0  # Count of votes
        
        # Update the vote for the specific user
        statistics[question][username] = vote
        
        # Convert vote to numeric if possible
        try:
            numeric_vote = float(vote)  # Attempt to convert to float
            vote_sums[question] += numeric_vote
            vote_counts[question] += 1
        except ValueError:
            # If the vote is not a number, skip it
            pass
    
    # Calculate average votes for each question
    averages = {}
    for question, total in vote_sums.items():
        count = vote_counts[question]
        averages[question] = "{:.2f}".format(total / count) if count > 0 else 'No Votes'
    
    return render_template('admin_statistics.html', statistics=statistics, all_users=all_users, averages=averages)


@app.route('/admin/clean_database', methods=['GET'])
@login_required
def clean_database():
    if current_user.user_type != 'Admin':
        flash('You do not have permission to perform this action', 'error')
        return redirect(url_for('statistics'))
    
    #Get all questions an delete them
    all_questions = Question.query.all()

    if all_questions:
        for question in all_questions:
            db.session.delete(question)
        db.session.commit()
        flash('All the questions have been deleted successfully', 'success')
    
    else:
        flash('No questions found to delete', 'info')
    return redirect(url_for('statistics'))

@app.route('/admin/delete_answers', methods=['GET'])
@login_required
def clean_database_answers():
    if current_user.user_type != 'Admin':
        flash('You do not have permission to perform this action', 'error')
        return redirect(url_for('statistics'))
    
    #Get all questions an delete them
    all_answers = UserAnswer.query.all()

    if all_answers:
        for answer in all_answers:
            db.session.delete(answer)
        db.session.commit()
        flash('All the questions have been deleted successfully', 'success')
    
    else:
        flash('No questions found to delete', 'info')
    return redirect(url_for('statistics'))


@app.route('/admin/delete_messages', methods=['GET'])
@login_required
def clean_database_messages():
    if current_user.user_type != 'Admin':
        flash('You do not have permission to perform this action', 'error')
        return redirect(url_for('statistics'))
    
    #Get all questions an delete them
    all_answers = AdditionalText.query.all()

    if all_answers:
        for answer in all_answers:
            db.session.delete(answer)
        db.session.commit()
        flash('All the questions have been deleted successfully', 'success')
    
    else:
        flash('No questions found to delete', 'info')
    return redirect(url_for('statistics'))

@app.route('/statistics', methods=['GET'])
@login_required
def statistics():
    all_answers = UserAnswer.query.all()
    all_additional_texts = AdditionalText.query.all()  # This retrieves all the messages

    # Retrieve all questions from the database
    all_questions = Question.query.all()
    
    statistics = {
        'total': len(all_answers),
        'question_stats': {},
        'averages': {}  # Store averages for each question
    }

    # Define emoji mappings
    emoji_mapping = {
        '1': 'Very Poor',
        '2': 'Poor',
        '3': 'Fair',
        '4': 'Below average',
        '5': 'Average',
        '6': 'Good',
        '7': 'Very Good',
        '8': 'Excellent',
        '9': 'Exceptional',
        '10': 'Perfect'
    }

    # Process answers for each question
    for question in all_questions:
        question_answers = [answer for answer in all_answers if answer.question == question.text]  # Use question.text

        # Count responses based on emojis
        counts = {
            'Very Poor': sum(1 for a in question_answers if a.answer == '1'),
            'Poor': sum(1 for a in question_answers if a.answer == '2'),
            'Fair': sum(1 for a in question_answers if a.answer == '3'),
            'Below average': sum(1 for a in question_answers if a.answer == '4'),
            'Average': sum(1 for a in question_answers if a.answer == '5'),
            'Good': sum(1 for a in question_answers if a.answer == '6'),
            'Very Good': sum(1 for a in question_answers if a.answer == '7'),
            'Excellent': sum(1 for a in question_answers if a.answer == '8'),
            'Exceptional': sum(1 for a in question_answers if a.answer == '9'),
            'Perfect': sum(1 for a in question_answers if a.answer == '10'),
        }

        statistics['question_stats'][question.text] = counts  # Use question.text for the key

        # Calculate average score for the question
        total_score = 0
        answer_count = 0
        for answer in question_answers:
            try:
                total_score += int(answer.answer)  # Convert the answer to an integer
                answer_count += 1
            except ValueError:
                pass  # Skip any non-numeric values

        # Calculate the average and store it in the statistics dictionary
        average = total_score / answer_count if answer_count > 0 else 'No Votes'
        statistics['averages'][question.text] = "{:.2f}".format(average) if isinstance(average, float) else average

    return render_template('statistics.html', statistics=statistics, additional_texts=all_additional_texts)

@app.route('/messages', methods=['GET'])
@login_required
def messages():
    # Query all additional messages from the current user
    all_additional_texts = AdditionalText.query.all()
    return render_template('messages.html', additional_texts=all_additional_texts)

@app.route('/admin/messages', methods=['GET'])
@login_required
def admin_messages():
    # Query all additional messages from the current user
    if current_user.user_type != 'Admin':
        return redirect(url_for('statistics'))
    all_additional_texts = AdditionalText.query.all()
    return render_template('admin_messages.html', additional_texts=all_additional_texts)

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
        # Check if the input is an email (simple check for @ character)
        login_identifier = form.username.data  # Assuming 'username' field is used for both
        if '@' in login_identifier:
            # If input contains an '@', treat it as an email
            user = User.query.filter_by(email=login_identifier).first()
        else:
            # Otherwise, treat it as a username
            user = User.query.filter_by(username=login_identifier).first()

        # Validate the user's credentials
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

#OPEN QUESTIONS
class OpenQuestion(db.Model):
    __tablename__ = 'open_questions'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)  # The question text
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

# Table to store users' answers to open questions
class UserOpenAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    question_id = db.Column(db.Integer, db.ForeignKey('open_questions.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    answer = db.Column(db.String(1000), nullable=False)  # Ensure 'answer' is a string field
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)

class AdminOpenQuestionForm(FlaskForm):
    question_text = StringField('Question', validators=[DataRequired()])
    submit = SubmitField('Add Question')

@app.route('/admin/add_open_question', methods=['GET', 'POST'])
@login_required
def add_open_question():
    if current_user.user_type != 'Admin':
        abort(403)
    
    form = AdminOpenQuestionForm()
    if form.validate_on_submit():
        question = OpenQuestion(text=form.question_text.data)
        db.session.add(question)
        db.session.commit()
        flash('Question added successfully!', 'success')
        return redirect(url_for('add_open_question'))
    
    return render_template('add_question_open.html', form=form, enumerate=enumerate)

class UserAnswerForm(FlaskForm):
    answer = TextAreaField('Answer', validators=[DataRequired()])

# Form for all questions (multiple answers)
class OpenQuestionsForm(FlaskForm):
    questions = FieldList(FormField(UserAnswerForm), min_entries=0)         

@app.route('/open_questions', methods=['GET', 'POST'], endpoint='open_questions')
@login_required
def answer_open_questions():
    questions_list = OpenQuestion.query.all()

    has_voted = UserOpenAnswer.query.filter_by(user_id=current_user.id).first()

    if has_voted:
        # User has already voted, redirect to another page or show a message
        return redirect(url_for('already_voted'))  # Redirect to a page that indicates they've already voted
 
    if not questions_list:
        flash('No questions available!', 'warning')
        return render_template('return_later.html', form=None, questions=questions_list)
 
    form = OpenQuestionsForm()  # Initialize the form

    if request.method == 'POST':
        # Populate the form with the answers submitted
        for question in questions_list:
            # Assuming that UserAnswerForm takes input name formatted as 'questions-<question_id>-answer'
            user_answer = request.form.get(f'questions-{question.id}-answer', "")
            question_form = UserAnswerForm(answer=user_answer)
            form.questions.append_entry(question_form)

        if form.validate_on_submit():
            try:
                for question in questions_list:
                    user_answer = form.questions[question.id - 1].answer.data
                    if not user_answer:
                        user_answer = "No answer provided."
                       
                    print(f"User Answer for question {question.id}: '{user_answer}' (Type: {type(user_answer)})")
                    answer_entry = UserOpenAnswer(
                        question_id=question.id,
                        user_id=current_user.id,
                        answer=user_answer,
                    )
                    db.session.add(answer_entry)
 
                db.session.commit()
                flash('Your answers have been submitted!', 'success')
                return redirect(url_for('open_questions'))
 
            except Exception as e:
                db.session.rollback()
                print(f"Error during commit: {e}")
                flash(f"An error occurred: {e}", 'danger')
        else:
            print("Form submission failed, validation errors:", form.errors)
 
    # Clear and populate fields if it's a GET request or the form is invalid
    form.questions.entries.clear()  # Clear existing entries for rendering
    form.questions.entries.clear()  # Clear existing entries for rendering
    for question in questions_list:
        # Create empty answer text areas for each question
        form.questions.append_entry(UserAnswerForm(answer=""))
 
    return render_template('open_questions.html', form=form, questions=questions_list, enumerate=enumerate)


class DeleteQuestionForm(FlaskForm):
    hidden_tag = HiddenField()

@app.route('/open_questions/delete_all', methods=['POST'])
@login_required
def delete_all_open_questions():
    if current_user.user_type != 'Admin':
        flash('You do not have permission to perform this action', 'error')
        return redirect(url_for('statistics'))

    try:
        # Delete all UserOpenAnswer entries
        UserOpenAnswer.query.delete()

        # Delete all OpenQuestion entries
        OpenQuestion.query.delete()

        db.session.commit()
        flash('All questions and their answers have been deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f"An error occurred: {e}", 'danger')

    return redirect(url_for('open_question_messages'))  # Redirect back to the open questions page

@app.route('/open_question/messages', methods=['GET'])
@login_required
def open_question_messages():
    if current_user.user_type != 'Admin':
        flash('You do not have permission to perform this action', 'error')
        return redirect(url_for('statistics'))

    questions_with_answers = db.session.query(OpenQuestion, UserOpenAnswer, User) \
        .outerjoin(UserOpenAnswer, OpenQuestion.id == UserOpenAnswer.question_id) \
        .outerjoin(User, User.id == UserOpenAnswer.user_id) \
        .order_by(User.username.asc()) \
        .all()

    delete_form = DeleteQuestionForm()  # Create form instance

    # Debug print form object
    print(delete_form)

    return render_template('answers_open_messages.html', questions_with_answers=questions_with_answers, form=delete_form)


@app.route('/open_question/delete/<int:question_id>', methods=['POST'])
@login_required
def delete_open_question(question_id):
    if current_user.user_type != 'Admin':
        flash('You do not have permission to perform this action', 'error')
        return redirect(url_for('statistics'))

    question = OpenQuestion.query.get_or_404(question_id)

    try:
        # Delete all answers associated with the question
        UserOpenAnswer.query.filter_by(question_id=question.id).delete()

        # Delete the question itself
        db.session.delete(question)
        db.session.commit()

        flash('Question and its answers have been deleted successfully!', 'success')
    except Exception as e:
        db.session.rollback()
        flash(f"An error occurred: {e}", 'danger')

    return redirect(url_for('open_question_messages'))  # Redirect to the messages page

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

