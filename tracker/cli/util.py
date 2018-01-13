from flask.cli import FlaskGroup

from tracker import create_app

cli = FlaskGroup(add_default_commands=True, create_app=create_app)
