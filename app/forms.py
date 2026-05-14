from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length


class URLForm(FlaskForm):
    url = StringField("Website URL", validators=[DataRequired(), Length(max=2048)])
    submit = SubmitField("Analyze")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(max=80)])
    password = PasswordField("Password", validators=[DataRequired(), Length(max=255)])
    submit = SubmitField("Sign in")
