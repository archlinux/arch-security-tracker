from flask_wtf import Form
from wtforms import StringField, BooleanField, PasswordField, SubmitField
from wtforms.validators import Required


class LoginForm(Form):
    username = StringField(u'Username', validators=[Required()])
    password = PasswordField(u'Password', validators=[Required()])
    remember_me = BooleanField(u'Remember me', default=False)
    login = SubmitField(u'login')
