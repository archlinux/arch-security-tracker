from app import db
from .enum import Severity, Remote


cve_id_regex = r'^CVE\-\d{4}\-\d+$'
cve_ids_regex = r'^(CVE\-\d{4}\-\d+[\r\n]*)+$'


class CVE(db.Model):
    __tablename__ = 'cve'
    id = db.Column(db.String(15), index=True, unique=True, primary_key=True)
    description = db.Column(db.String())
    severity = db.Column(Severity.as_type(), nullable=False, default=Severity.unknown)
    remote = db.Column(Remote.as_type(), nullable=False, default=Remote.unknown)
    notes = db.Column(db.String())

    def __repr__(self):
        return '{}'.format(self.id)
