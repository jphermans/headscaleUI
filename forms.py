from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, SelectField
from wtforms.validators import DataRequired

class UserForm(FlaskForm):
    name = StringField("Username", validators=[DataRequired()])
    submit = SubmitField("Add User")

class NodeForm(FlaskForm):
    name = StringField("Node Name", validators=[DataRequired()])
    user = SelectField(
        "Assign to User",
        validators=[DataRequired()],
        choices=[]
    )
    submit = SubmitField("Add Node")

class APIKeyForm(FlaskForm):
    description = StringField("Description", validators=[DataRequired()])
    validity = SelectField(
        "Validity Period",
        choices=[
            ("87600h", "10 Years"),
            ("8760h", "1 Year"),
            ("720h", "30 Days"),
            ("168h", "7 Days"),
            ("24h", "1 Day"),
        ],
        default="8760h",
        validators=[DataRequired()]
    )
    submit = SubmitField("Generate API Key")

class LoginForm(FlaskForm):
    api_key = StringField("API Key", validators=[DataRequired()], render_kw={"type": "password"})
    submit = SubmitField("Login")