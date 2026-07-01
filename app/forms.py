from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField
from wtforms.validators import DataRequired, Length


class URLForm(FlaskForm):
    url = StringField("Website URL or domain", validators=[DataRequired(), Length(max=2048)])
    submit = SubmitField("Analyze")
