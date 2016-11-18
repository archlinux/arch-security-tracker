from app import db
from .enum import UserRole


class User(db.Model):

    NAME_LENGTH = 32
    EMAIL_LENGTH = 128
    SALT_LENGTH = 20
    PASSWORD_LENGTH = 80
    PASSWORD_MIN_LENGTH = 10

    __tablename__ = 'user'
    id = db.Column(db.Integer(), index=True, unique=True, primary_key=True, autoincrement=True)
    name = db.Column(db.String(NAME_LENGTH), index=True, unique=True, nullable=False)
    email = db.Column(db.String(EMAIL_LENGTH), index=True, unique=True, nullable=False)
    salt = db.Column(db.String(SALT_LENGTH), nullable=False)
    password = db.Column(db.String(SALT_LENGTH), nullable=False)
    role = db.Column(UserRole.as_type(), nullable=False, default=UserRole.reporter)
    active = db.Column(db.Boolean(), nullable=False, default=True)

    is_authenticated = False
    is_anonymous = False

    @property
    def is_active(self):
        return self.active

    def get_id(self):
        return "{}".format(self.id)

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<User %r>' % (self.name)


class Guest(User):
    def __init__(self):
        super().__init__()
        self.name = 'Guest'
        self.active = False
        self.is_anonymous = True
        self.is_authenticated = False
        self.role = UserRole.guest

    def get_id(self):
        return None
