from datetime import datetime
from app import db
from .enum import Status


pkgname_regex = r'^([a-z\d@\.\_\+]+[\-]*)+$'
pkgnames_regex = r'^(([a-z\d@\.\_\+]+[\-]*)+[\r\n]*)+$'
pkgver_regex = r'^(\d+:)?([\w]+[\._]*)+\-\d+$'
vulnerability_group_regex = r'^AVG-\d+$'


class CVEGroup(db.Model):
    __tablename__ = 'cve_group'
    id = db.Column(db.Integer(), index=True, unique=True, primary_key=True, autoincrement=True)
    pkgname = db.Column(db.String(32), nullable=False, index=True)
    affected = db.Column(db.String(24), nullable=False)
    fixed = db.Column(db.String(24))
    status = db.Column(Status.as_type(), nullable=False, default=Status.unknown, index=True)
    bug_ticket = db.Column(db.String(8))
    notes = db.Column(db.String(120))
    created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    def __repr__(self):
        return '<CVEGroup %r>' % (self.id)
