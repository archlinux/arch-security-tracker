from datetime import datetime

from tracker import db
from tracker.model.cve import issue_types
from tracker.model.enum import Publication

advisory_regex = r'^(ASA\-(\d{6})\-(\d+))$'
advisory_types = list(filter(lambda e: e != 'unknown', issue_types))
advisory_types.insert(0, 'multiple issues')


class Advisory(db.Model):
    WORKAROUND_LENGTH = 4096
    IMPACT_LENGTH = 4096
    CONTENT_LENGTH = 65536
    REFERENCE_LENGTH = 120

    __versioned__ = {}
    __tablename__ = 'advisory'

    id = db.Column(db.String(15), index=True, unique=True, primary_key=True)
    group_package_id = db.Column(db.Integer(), db.ForeignKey('cve_group_package.id'), nullable=False, unique=True, index=True)
    advisory_type = db.Column(db.String(64), default='multiple issues', nullable=False)
    publication = db.Column(Publication.as_type(), nullable=False, default=Publication.scheduled)
    workaround = db.Column(db.String(WORKAROUND_LENGTH), nullable=True)
    impact = db.Column(db.String(IMPACT_LENGTH), nullable=True)
    content = db.Column(db.String(CONTENT_LENGTH), nullable=True)
    created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    changed = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    reference = db.Column(db.String(REFERENCE_LENGTH), nullable=True)

    group_package = db.relationship("CVEGroupPackage")

    def __repr__(self):
        return '<Advisory {}>'.format(self.id)
