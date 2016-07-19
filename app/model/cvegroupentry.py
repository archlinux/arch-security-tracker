from app import db


class CVEGroupEntry(db.Model):
    id = db.Column(db.Integer(), index=True, unique=True, primary_key=True)
    group_id = db.Column(db.Integer(), db.ForeignKey('cve_group.id'), nullable=False)
    cve_id = db.Column(db.String(15), db.ForeignKey('cve.id'), nullable=False)

    group = db.relationship("CVEGroup")
    cve = db.relationship("CVE")

    __tablename__ = 'cve_group_entry'
    __table_args__ = (db.Index('cve_group_entry__group_cve_idx', group_id, cve_id, unique=True),)

    def __repr__(self):
        return '<CVEGroupEntry %r from %r referencing %r>' % (self.id, self.group_id, self.cve_id)
