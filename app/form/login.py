from .base import BaseForm
from wtforms import StringField, BooleanField, PasswordField, SubmitField
from wtforms.validators import DataRequired


class LoginForm(BaseForm):
    username = StringField(u'Username', validators=[DataRequired()])
    password = PasswordField(u'Password', validators=[DataRequired()])
    remember_me = BooleanField(u'Remember me', default=False)
    login = SubmitField(u'login')
