from flask import render_template, redirect, flash
from app import app, db
from app.user import administrator_required
from app.form.admin import CreateUserForm
from app.model.user import User
from app.model.enum import UserRole
from app.user import random_string, hash_password


@app.route('/admin/user/create', methods=['GET', 'POST'])
@administrator_required
def create_user():
    form = CreateUserForm()
    if not form.validate_on_submit():
        return render_template('form/create_user.html',
                               title='Create User',
                               form=form,
                               User=User)

    password = random_string() if not form.password.data else form.password.data
    salt = random_string()
    user = db.create(User,
                     name=form.username.data,
                     email=form.email.data,
                     salt=salt,
                     password=hash_password(password, salt),
                     role=UserRole.fromstring(form.role.data))
    db.session.commit()

    flash('Created {} with password: {}'.format(user.name, password))
    return redirect('/')
