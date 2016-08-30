from app import db
from .enum import Severity, Remote


cve_id_regex = r'^(CVE\-\d{4}\-\d+)$'
issue_types = [
    'Unknown',
    'access restriction bypass',
    'arbitrary code execution',
    'arbitrary command execution',
    'arbitrary file overwrite',
    'arbitrary filesystem access',
    'arbitrary file upload',
    'authentication bypass',
    'certificate verification bypass',
    'content spoofing',
    'cross-site request forgery',
    'cross-site scripting',
    'denial of service',
    'directory traversal',
    'improper cryptographic calculation',
    'information disclosure',
    'insufficient validation',
    'man-in-the-middle',
    'open redirect',
    'private key recovery',
    'privilege escalation',
    'proxy injection',
    'same-origin policy bypass',
    'sandbox escape',
    'session hijacking',
    'signature forgery',
    'silent downgrade',
    'sql injection',
    'time alteration',
    'url request injection',
    'xml external entity injection'
]


class CVE(db.Model):

    NOTES_LENGTH = 4096
    DESCRIPTION_LENGTH = 4096

    __tablename__ = 'cve'
    id = db.Column(db.String(15), index=True, unique=True, primary_key=True)
    issue_type = db.Column(db.String(64), default='unknown')
    description = db.Column(db.String(DESCRIPTION_LENGTH))
    severity = db.Column(Severity.as_type(), nullable=False, default=Severity.unknown)
    remote = db.Column(Remote.as_type(), nullable=False, default=Remote.unknown)
    notes = db.Column(db.String(NOTES_LENGTH))

    def __repr__(self):
        return '{}'.format(self.id)
