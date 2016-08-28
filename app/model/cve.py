from app import db
from .enum import Severity, Remote


cve_id_regex = r'^(CVE\-\d{4}\-\d+)$'


class CVE(db.Model):

    NOTES_LENGTH = 4096
    DESCRIPTION_LENGTH = 4096

    __tablename__ = 'cve'
    id = db.Column(db.String(15), index=True, unique=True, primary_key=True)
    description = db.Column(db.String(DESCRIPTION_LENGTH))
    severity = db.Column(Severity.as_type(), nullable=False, default=Severity.unknown)
    remote = db.Column(Remote.as_type(), nullable=False, default=Remote.unknown)
    notes = db.Column(db.String(NOTES_LENGTH))

    def __repr__(self):
        return '{}'.format(self.id)
