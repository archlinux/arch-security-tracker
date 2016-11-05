from flask import render_template, redirect, url_for
from flask_login import login_user, logout_user
from app import app
from app.form import LoginForm
from app.model.user import User


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        form.user.is_authenticated = True
        login_user(form.user)
        return redirect(url_for('index'))
    return render_template('login.html',
                           title='Login',
                           form=form,
                           User=User)


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    return redirect(url_for('index'))
