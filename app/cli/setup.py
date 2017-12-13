from click import echo, option, pass_context, password_option, Choice, BadParameter
from re import match, IGNORECASE
from pathlib import Path
from os.path import exists, join
from os import rename
from sys import exit

from config import basedir, TRACKER_PASSWORD_LENGTH_MIN, TRACKER_PASSWORD_LENGTH_MAX
from app.model.user import User, username_regex
from app.model.enum import UserRole
from . import cli


@cli.group()
def setup():
    """Setup and bootstrap the application."""
    pass


@setup.command()
@option('--purge', is_flag=True, help='Purge all data and tables.')
@pass_context
def bootstrap(ctx, purge=False):
    """Bootstrap the environment.

    Create all folders, database tables and other things that are required to
    run the application.

    An initial administrator user must be created separately."""

    from app import db

    def mkdir(path):
        Path(path).mkdir(parents=True, exist_ok=True)

    echo('Creating folders...', nl=False)
    mkdir(join(basedir, 'pacman/cache'))
    mkdir(join(basedir, 'pacman/log'))
    mkdir(join(basedir, 'pacman/arch/x86_64/db'))
    echo('done')

    if purge:
        echo('Purging the database...', nl=False)
        db.drop_all()
        echo('done')
        ctx.invoke(vacuum)

    echo('Initializing the database...', nl=False)
    db.create_all()
    echo('done')


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
    from app.user import random_string
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

    from app import db
    from app.user import random_string, hash_password

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


@setup.command()
def vacuum():
    """Perform vacuum on the database."""

    from app import db

    echo('Performing database vacuum...', nl=False)
    db.session.execute('VACUUM')
    echo('done')


@setup.command()
@option('--integrity/--no-integrity', default=True, help='Check database integrity.')
@option('--foreign-key/--no-foreign-key', default=True, help='Check foreign keys.')
def check(integrity, foreign_key):
    """Database integrity checks.

    Performs database integrity and foreign key checks and displays the
    results if any errors are found."""

    from app import db

    integrity_errors = False
    foreign_key_errors = False

    if integrity:
        echo('Checking database integrity...', nl=False)
        integrity_result = db.session.execute('PRAGMA integrity_check')
        integrity_errors = list(filter(lambda result: result[0] != 'ok', integrity_result.fetchall()))
        if not integrity_errors:
            echo('ok')
        else:
            echo('failed')
            for error in integrity_errors:
                echo('{}'.format(error), err=True)

    if foreign_key:
        echo('Checking database foreign keys...', nl=False)
        foreign_key_errors = db.session.execute('PRAGMA foreign_key_check').fetchall()
        if not foreign_key_errors:
            echo('ok')
        else:
            echo('failed')
            header_table = 'table'
            header_row = 'row id'
            header_parent = 'parent'
            header_fkey = 'fkey idx'
            max_table = max(list(map(lambda error: len(error[0]), foreign_key_errors)) + [len(header_table)])
            max_row = max(list(map(lambda error: len(str(error[1])), foreign_key_errors)) + [len(header_row)])
            max_parent = max(list(map(lambda error: len(error[2]), foreign_key_errors)) + [len(header_parent)])
            max_fkey = max(list(map(lambda error: len(str(error[3])), foreign_key_errors)) + [len(header_fkey)])
            header = ' {} | {} | {} | {} '.format(header_table.ljust(max_table),
                                                  header_row.ljust(max_row),
                                                  header_parent.ljust(max_parent),
                                                  header_fkey.ljust(max_fkey))
            echo('=' * len(header), err=True)
            echo(header, err=True)
            echo('=' * len(header), err=True)
            for error in foreign_key_errors:
                table = error[0]
                row = str(error[1])
                parent = error[2]
                fkey = str(error[3])
                echo(' {} | {} | {} | {} '.format(table.ljust(max_table),
                                                  row.rjust(max_row),
                                                  parent.ljust(max_parent),
                                                  fkey.rjust(max_fkey)), err=True)

    if integrity_errors or foreign_key_errors:
        exit(1)
