# forms.py
from flask_wtf import FlaskForm
from wtforms import HiddenField

class DeleteQuestionForm(FlaskForm):
    hidden_tag = HiddenField()  # CSRF token