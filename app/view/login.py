from flask import render_template, redirect, url_for
from flask_login import login_user, logout_user, current_user
from app import app
from app.user import user_assign_new_token, user_invalidate
from app.form import LoginForm
from app.model.user import User
from config import TRACKER_PASSWORD_LENGTH_MIN, TRACKER_PASSWORD_LENGTH_MAX


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if not form.validate_on_submit():
        return render_template('login.html',
                               title='Login',
                               form=form,
                               User=User,
                               password_length={'min': TRACKER_PASSWORD_LENGTH_MIN,
                                                'max': TRACKER_PASSWORD_LENGTH_MAX})

    user = user_assign_new_token(form.user)
    user.is_authenticated = True
    login_user(user)
    return redirect(url_for('index'))


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    if not current_user.is_authenticated:
        return redirect(url_for('index'))

    user_invalidate(current_user)
    logout_user()
    return redirect(url_for('index'))
