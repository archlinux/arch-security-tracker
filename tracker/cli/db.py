from click import echo
from click import option
from click import pass_context
from flask.cli import with_appcontext
from flask_migrate.cli import db as db_cli

from tracker import db


def abort_if_false(ctx, param, value):
    if not value:
        ctx.abort()


@db_cli.command()
@with_appcontext
def vacuum():
    """Perform vacuum on the database."""

    echo('Performing database vacuum...', nl=False)
    db.session.execute('VACUUM')
    echo('done')


@db_cli.command()
@option('--yes', is_flag=True, callback=abort_if_false,
        expose_value=False, prompt='Are you sure you want to drop the database?')
@with_appcontext
@pass_context
def drop(ctx):
    """Drop the database."""

    echo('Dropping database...', nl=False)
    db.drop_all()
    echo('done')
    ctx.invoke(vacuum)


@db_cli.command()
@option('--purge', is_flag=True, help='Purge all data and tables.')
@with_appcontext
@pass_context
def initdb(ctx, purge):
    """Initialize the database and all tables."""

    if purge:
        ctx.invoke(drop)

    echo('Initializing database...', nl=False)
    db.create_all()
    echo('done')


@db_cli.command()
@option('--integrity/--no-integrity', default=True, help='Check database integrity.')
@option('--foreign-key/--no-foreign-key', default=True, help='Check foreign keys.')
@with_appcontext
def check(integrity, foreign_key):
    """Database integrity checks.

    Performs database integrity and foreign key checks and displays the
    results if any errors are found."""

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
