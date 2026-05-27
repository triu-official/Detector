from __future__ import annotations

from flask_wtf import FlaskForm
from flask_wtf.file import FileAllowed, FileRequired
from wtforms import FileField, PasswordField, StringField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length, Optional


class URLForm(FlaskForm):
    url = StringField('Website URL', validators=[DataRequired(), Length(max=2048)])
    submit = SubmitField('Analyze')


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(max=80)])
    password = PasswordField('Password', validators=[DataRequired(), Length(max=255)])
    submit = SubmitField('Sign in')


class BlacklistForm(FlaskForm):
    domain = StringField('Domain', validators=[DataRequired(), Length(max=255)])
    reason = TextAreaField('Reason', validators=[Optional(), Length(max=500)])
    submit = SubmitField('Add domain')


class BatchUploadForm(FlaskForm):
    file = FileField('CSV file', validators=[FileRequired(), FileAllowed(['csv'], 'CSV files only')])
    submit = SubmitField('Analyze CSV')
