from flask import flash
from flask import redirect
from flask import render_template
from flask_login import current_user
from flask_login import login_required

from config import TRACKER_PASSWORD_LENGTH_MAX
from config import TRACKER_PASSWORD_LENGTH_MIN
from tracker import db
from tracker import tracker
from tracker.form.user import UserPasswordForm
from tracker.user import hash_password
from tracker.user import random_string


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
