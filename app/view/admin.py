from flask import render_template, redirect, flash
from app import app, db
from app.user import administrator_required
from app.form.admin import CreateUserForm
from app.model.user import User
from app.user import gen_salt, hash_password


@app.route('/admin/user/create', methods=['GET', 'POST'])
@administrator_required
def create_user():
    form = CreateUserForm()
    if not form.validate_on_submit():
        return render_template('form/create_user.html',
                               title='Create User',
                               form=form,
                               User=User)

    password = gen_salt() if not form.password.data else form.password.data
    salt = gen_salt()
    user = db.create(User, name=form.username.data,
                     email=form.email.data, salt=salt,
                     password=hash_password(password, salt))
    db.session.commit()

    flash('Created {} with password: {}'.format(user.name, password))
    return redirect('/')
