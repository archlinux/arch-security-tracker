from os.path import abspath, dirname
from configparser import ConfigParser
from glob import glob

basedir = abspath(dirname(__file__))

config = ConfigParser()
config_files = sorted(glob('{}/config/*.conf'.format(basedir)))
for config_file in config_files:
    config.read(config_file)

config_tracker = config['tracker']
TRACKER_ADVISORY_URL = config_tracker['advisory_url']
TRACKER_BUGTRACKER_URL = config_tracker['bugtracker_url']

config_sqlite = config['sqlite']
SQLITE_JOURNAL_MODE = config_sqlite['journal_mode']
SQLITE_TEMP_STORE = config_sqlite['temp_store']
SQLITE_SYNCHRONOUS = config_sqlite['synchronous']
SQLITE_MMAP_SIZE = config_sqlite.getint('mmap_size')

config_sqlalchemy = config['sqlalchemy']
SQLALCHEMY_DATABASE_URI = config_sqlalchemy['database_uri'].replace('{{BASEDIR}}', basedir)
SQLALCHEMY_MIGRATE_REPO = config_sqlalchemy['migrate_repo'].replace('{{BASEDIR}}', basedir)
SQLALCHEMY_ECHO = config_sqlalchemy.getboolean('echo')
SQLALCHEMY_TRACK_MODIFICATIONS = config_sqlalchemy.getboolean('track_modifications')

config_flask = config['flask']
CSRF_ENABLED = config_flask.getboolean('csrf')
SECRET_KEY = config_flask['secret_key']

config_pacman = config['pacman']
PACMAN_HANDLE_CACHE_TIME = config_pacman.getint('handle_cache_time')
