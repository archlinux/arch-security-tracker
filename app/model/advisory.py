from app import db
from app.model.cve import issue_types
from app.model.enum import Publication
from datetime import datetime


advisory_regex = r'^(ASA\-\d{6}\-\d+)$'
advisory_types = list(filter(lambda e: e is not 'unknown', issue_types))
advisory_types.insert(0, 'multiple issues')


class Advisory(db.Model):
    __tablename__ = 'advisory'
    id = db.Column(db.String(15), index=True, unique=True, primary_key=True)
    group_package_id = db.Column(db.Integer(), db.ForeignKey('cve_group_package.id'), nullable=False, unique=True, index=True)
    advisory_type = db.Column(db.String(64), default='multiple issues', nullable=False)
    publication = db.Column(Publication.as_type(), nullable=False, default=Publication.scheduled)
    created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    reference = db.Column(db.String(120), nullable=True)

    group_package = db.relationship("CVEGroupPackage")

    def __repr__(self):
        return '<Advisory {}>'.format(self.id)
