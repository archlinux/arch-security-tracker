from flask import render_template, redirect, flash
from flask_login import login_required, current_user
from tracker import tracker, db
from tracker.form.user import UserPasswordForm
from tracker.user import random_string, hash_password
from config import TRACKER_PASSWORD_LENGTH_MIN, TRACKER_PASSWORD_LENGTH_MAX


@tracker.route('/profile', methods=['GET', 'POST'])
@login_required
def edit_own_user_profile():
    form = UserPasswordForm()
    if not form.validate_on_submit():
        return render_template('form/profile.html',
                               title='Edit profile',
                               form=form,
                               password_length={'min': TRACKER_PASSWORD_LENGTH_MIN,
                                                'max': TRACKER_PASSWORD_LENGTH_MAX})

    user = current_user
    user.salt = random_string()
    user.password = hash_password(form.password.data, user.salt)
    db.session.commit()

    flash('Profile saved')
    return redirect('/')
