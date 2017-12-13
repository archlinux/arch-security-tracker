from flask import render_template, redirect, url_for
from flask_login import login_user, logout_user, current_user
from app import main
from app.user import user_assign_new_token, user_invalidate
from app.form import LoginForm
from app.model.user import User
from config import TRACKER_PASSWORD_LENGTH_MIN, TRACKER_PASSWORD_LENGTH_MAX
from werkzeug.exceptions import Unauthorized


@main.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('main.index'))

    form = LoginForm()
    if not form.validate_on_submit():
        status_code = Unauthorized.code if form.is_submitted() else 200
        return render_template('login.html',
                               title='Login',
                               form=form,
                               User=User,
                               password_length={'min': TRACKER_PASSWORD_LENGTH_MIN,
                                                'max': TRACKER_PASSWORD_LENGTH_MAX}), status_code

    user = user_assign_new_token(form.user)
    user.is_authenticated = True
    login_user(user)
    return redirect(url_for('main.index'))


@main.route('/logout', methods=['GET', 'POST'])
def logout():
    if not current_user.is_authenticated:
        return redirect(url_for('main.index'))

    user_invalidate(current_user)
    logout_user()
    return redirect(url_for('main.index'))
