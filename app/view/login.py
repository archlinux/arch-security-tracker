from flask import render_template, flash, redirect
from app import app
from app.form import LoginForm


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        flash('Login requested for Username="%s", remember_me=%s' %
              (form.username.data, str(form.remember_me.data)))
        return redirect('/index')
    return render_template('login.html',
                           title='Login',
                           form=form)
