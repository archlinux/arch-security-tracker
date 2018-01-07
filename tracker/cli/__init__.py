from flask.cli import FlaskGroup
from tracker import create_app

cli = FlaskGroup(add_default_commands=True, create_app=create_app)

from .run import *
from .shell import *
from .update import *
from .setup import *
