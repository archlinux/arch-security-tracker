from datetime import datetime
from app import db
from .enum import Status, Severity


pkgname_regex = r'^([a-z\d@\.\_\+-]+)$'
pkgver_regex = r'^(\d+:)?([\w]+[\._+]*)+\-\d+(\.\d+)?$'
vulnerability_group_regex = r'^AVG-\d+$'


class CVEGroup(db.Model):

    REFERENCES_LENGTH = 4096
    NOTES_LENGTH = 4096
    __tablename__ = 'cve_group'
    id = db.Column(db.Integer(), index=True, unique=True, primary_key=True, autoincrement=True)
    status = db.Column(Status.as_type(), nullable=False, default=Status.unknown, index=True)
    severity = db.Column(Severity.as_type(), nullable=False, default=Severity.unknown)
    affected = db.Column(db.String(32), nullable=False)
    fixed = db.Column(db.String(32))
    bug_ticket = db.Column(db.String(9))
    reference = db.Column(db.String(REFERENCES_LENGTH))
    notes = db.Column(db.String(NOTES_LENGTH))
    created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    advisory_qualified = db.Column(db.Boolean(), default=True, nullable=False)

    issues = db.relationship("CVEGroupEntry", back_populates="group", cascade="all,delete")
    packages = db.relationship("CVEGroupPackage", back_populates="group", cascade="all,delete")

    @property
    def name(self):
        return 'AVG-{}'.format(self.id)

    def __str__(self):
        return self.name

    def __repr__(self):
        return '<CVEGroup %r>' % (self.id)
