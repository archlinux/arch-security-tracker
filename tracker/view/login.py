import pyotp

from flask import redirect
from flask import render_template
from flask import url_for
from flask import session
from flask_login import current_user
from flask_login import login_user
from flask_login import logout_user
from werkzeug.exceptions import Unauthorized

from config import TRACKER_PASSWORD_LENGTH_MAX
from config import TRACKER_PASSWORD_LENGTH_MIN
from config import TRACKER_OTP_FORMAT
from config import TRACKER_ENABLE_TWO_FACTOR
from tracker import tracker
from tracker.form import LoginForm
from tracker.form import OTPForm
from tracker.model.user import User
from tracker.user import user_assign_new_token
from tracker.user import user_invalidate


@tracker.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('tracker.two_factor'))

    form = LoginForm()
    if not form.validate_on_submit():
        status_code = Unauthorized.code if form.is_submitted() else 200
        return render_template('login.html',
                               title='Login',
                               form=form,
                               User=User,
                               password_length={'min': TRACKER_PASSWORD_LENGTH_MIN,
                                                'max': TRACKER_PASSWORD_LENGTH_MAX}), status_code
    if TRACKER_ENABLE_TWO_FACTOR:
        session['two_factor'] = form.user.name
        return redirect(url_for('tracker.two_factor'))
    user = user_assign_new_token(form.user)
    login_user(user)
    return redirect(url_for('tracker.index'))


@tracker.route('/twofactor', methods=['GET', 'POST'])
def two_factor():
    if current_user.is_authenticated:
        return redirect(url_for('tracker.index'))
    if not session.get('two_factor'):
        return redirect(url_for('tracker.login'))
    user = User.query.filter(User.name == session['two_factor']).first()
    if not user.otp_token:
        user.otp_token = pyotp.random_base32()
        user.first_time_login_otp = True
    form = OTPForm()
    if not form.validate_on_submit():
        status_code = Unauthorized.code if form.is_submitted() else 200
        return render_template('two_factor.html',
                               title='Two Factor Login',
                               User=User,
                               form=form,
                               display_qr=user.first_time_login_otp,
                               otp_string=TRACKER_OTP_FORMAT.format(user.name, user.otp_token),
                               otp_code_length={'max': 6}), status_code

    user = user_assign_new_token(user)
    login_user(user)
    return redirect(url_for('tracker.index'))


@tracker.route('/logout', methods=['GET', 'POST'])
def logout():
    if not current_user.is_authenticated:
        return redirect(url_for('tracker.index'))

    user_invalidate(current_user)
    logout_user()
    return redirect(url_for('tracker.index'))
