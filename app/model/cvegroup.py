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
    affected = db.Column(db.String(32), nullable=False)
    fixed = db.Column(db.String(32))
    status = db.Column(Status.as_type(), nullable=False, default=Status.unknown, index=True)
    bug_ticket = db.Column(db.String(9))
    notes = db.Column(db.String(4096))
    created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    @property
    def name(self):
        return 'AVG-{}'.format(self.id)

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<CVEGroup %r>' % (self.id)
