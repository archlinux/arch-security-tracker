from datetime import datetime

from tracker import db
from tracker.util import issue_to_numeric

from .enum import Remote
from .enum import Severity

cve_id_regex = r'^(CVE\-\d{4}\-\d{4,})$'
issue_types = [
    'unknown',
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
    'incorrect calculation',
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

    DESCRIPTION_LENGTH = 4096
    REFERENCES_LENGTH = 4096
    NOTES_LENGTH = 4096

    __versioned__ = {}
    __tablename__ = 'cve'

    id = db.Column(db.String(15), index=True, unique=True, primary_key=True)
    issue_type = db.Column(db.String(64), default='unknown')
    description = db.Column(db.String(DESCRIPTION_LENGTH))
    severity = db.Column(Severity.as_type(), nullable=False, default=Severity.unknown)
    remote = db.Column(Remote.as_type(), nullable=False, default=Remote.unknown)
    reference = db.Column(db.String(REFERENCES_LENGTH))
    notes = db.Column(db.String(NOTES_LENGTH))
    created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    changed = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    @staticmethod
    def new(id):
        return CVE(id=id,
                   issue_type='unknown',
                   description='',
                   severity=Severity.unknown,
                   remote=Remote.unknown,
                   reference='',
                   notes='')

    def __repr__(self):
        return '{}'.format(self.id)

    @property
    def numerical_repr(self):
        return issue_to_numeric(self.id)

    def __gt__(self, other):
        return self.numerical_repr > other.numerical_repr

    def __lt__(self, other):
        return self.numerical_repr < other.numerical_repr
