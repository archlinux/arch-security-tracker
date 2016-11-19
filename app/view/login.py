from flask import render_template, redirect, url_for
from flask_login import login_user, logout_user, current_user
from app import app
from app.form import LoginForm
from app.model.user import User
from config import TRACKER_PASSWORD_LENGTH_MIN, TRACKER_PASSWORD_LENGTH_MAX


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))

    form = LoginForm()
    if form.validate_on_submit():
        form.user.is_authenticated = True
        login_user(form.user)
        return redirect(url_for('index'))
    return render_template('login.html',
                           title='Login',
                           form=form,
                           User=User,
                           password_length={'min': TRACKER_PASSWORD_LENGTH_MIN,
                                            'max': TRACKER_PASSWORD_LENGTH_MAX})


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    current_user.is_authenticated = False
    logout_user()
    return redirect(url_for('index'))
