from .base import BaseForm
from app.model.user import User
from app.user import hash_password
from wtforms import StringField, BooleanField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length


class LoginForm(BaseForm):
    username = StringField(u'Username', validators=[DataRequired(), Length(max=User.NAME_LENGTH)])
    password = PasswordField(u'Password', validators=[DataRequired(), Length(max=User.PASSWORD_LENGTH)])
    remember_me = BooleanField(u'Remember me', default=False)
    login = SubmitField(u'login')

    def validate(self):
        rv = BaseForm.validate(self)
        if not rv:
            return False

        def fail():
            self.password.errors.append('Invalid username or password.')
            return False
        user = User.query.filter(User.name == self.username.data).first()
        if not user:
            hash_password(self.password.data, 'the cake is a lie!')
            return fail()
        if user.password != hash_password(self.password.data, user.salt):
            return fail()
        return True
