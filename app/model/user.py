from datetime import datetime
from app import db
from .enum import OrderedDatabaseEnum


class UserRole(OrderedDatabaseEnum):
    administrator = 'Administrator', 1
    security_team = 'Security Team', 2
    reporter = 'Reporter', 3


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

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<User %r>' % (self.name)
