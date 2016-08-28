from app import db
from app.model.enum import Publication
from datetime import datetime


class Advisory(db.Model):
    __tablename__ = 'advisory'
    id = db.Column(db.String(15), index=True, unique=True, primary_key=True)
    group_package_id = db.Column(db.Integer(), db.ForeignKey('cve_group_package.id'), nullable=False, unique=True, index=True)
    publication = db.Column(Publication.as_type(), nullable=False, default=Publication.scheduled)
    created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)

    group_package = db.relationship("CVEGroupPackage")

    def __repr__(self):
        return '<Advisory {}>'.format(self.id)
