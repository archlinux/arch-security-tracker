from os import rename
from os.path import exists
from os.path import join
from pathlib import Path
from re import IGNORECASE
from re import match
from sys import exit

from click import BadParameter
from click import Choice
from click import echo
from click import option
from click import pass_context
from click import password_option

from config import TRACKER_PASSWORD_LENGTH_MAX
from config import TRACKER_PASSWORD_LENGTH_MIN
from config import basedir
from tracker.model.enum import UserRole
from tracker.model.user import User
from tracker.model.user import username_regex

from .db import initdb
from .util import cli


@cli.group()
def setup():
    """Setup and bootstrap the application."""
    pass


@setup.command()
@option('--purge', is_flag=True, help='Purge all data and tables.')
@pass_context
def database(ctx, purge=False):
    """Initialize the database tables."""

    # Auto rename old database for compatibility
    db_old = join(basedir, 'app.db')
    db_new = join(basedir, 'tracker.db')
    if exists(db_old) and not exists(db_new):
        echo('Renaming old database file...', nl=False)
        rename(db_old, db_new)
        echo('done')

    ctx.invoke(initdb, purge=purge)


@setup.command()
@option('--purge', is_flag=True, help='Purge all data and tables.')
@pass_context
def bootstrap(ctx, purge=False):
    """Bootstrap the environment.

    Create all folders, database tables and other things that are required to
    run the application.

    An initial administrator user must be created separately."""

    def mkdir(path):
        Path(path).mkdir(parents=True, exist_ok=True)

    echo('Creating folders...', nl=False)
    mkdir(join(basedir, 'pacman/cache'))
    mkdir(join(basedir, 'pacman/log'))
    mkdir(join(basedir, 'pacman/arch/x86_64/db'))
    echo('done')

    ctx.invoke(database, purge=purge)


def validate_username(ctx, param, username):
    if len(username) > User.NAME_LENGTH:
        raise BadParameter('must not exceed {} characters'.format(User.NAME_LENGTH))
    if not username or not match(username_regex, username):
        raise BadParameter('must match {}'.format(username_regex))
    return username


def validate_email(ctx, param, email):
    email_regex = r'^.+@([^.@][^@]+)$'
    if not email or not match(email_regex, email, IGNORECASE):
        raise BadParameter('must match {}'.format(email_regex))
    return email


def validate_password(ctx, param, password):
    from tracker.user import random_string
    if not password or 'generated' == password:
        password = random_string()
        print('Generated password: {}'.format(password))
    if len(password) > TRACKER_PASSWORD_LENGTH_MAX or len(password) < TRACKER_PASSWORD_LENGTH_MIN:
        raise BadParameter('Error: password must be between {} and {} characters.'
                           .format(TRACKER_PASSWORD_LENGTH_MIN, TRACKER_PASSWORD_LENGTH_MAX))
    return password


@setup.command()
@option('--username', prompt=True, callback=validate_username, help='Username used to log in.')
@option('--email', prompt='E-mail', callback=validate_email, help='E-mail address of the user.')
@password_option(default='generated', callback=validate_password, help='Password for the user.')
@option('--role', type=Choice([role.name for role in UserRole]), default=UserRole.reporter.name,
        prompt=True, callback=lambda ctx, param, role: UserRole.fromstring(role),
        help='Permission group of the user.')
@option('--active/--inactive', default=True, prompt=True, help='Enable or disable the user.')
def user(username, email, password, role, active):
    """Create a new application user."""

    from tracker import db
    from tracker.user import hash_password
    from tracker.user import random_string

    user_by_name = db.get(User, name=username)
    if user_by_name:
        echo('Error: username already exists', err=True)
        exit(1)

    user_by_email = db.get(User, email=email)
    if user_by_email:
        echo('Error: e-mail already exists', err=True)
        exit(1)

    user = User()
    user.name = username
    user.email = email
    user.salt = random_string()
    user.password = hash_password(password, user.salt)
    user.role = role
    user.active = active

    db.session.add(user)
    db.session.commit()
