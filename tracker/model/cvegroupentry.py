from tracker import db


class CVEGroupEntry(db.Model):

    __tablename__ = 'cve_group_entry'
    __versioned__ = {}

    id = db.Column(db.Integer(), index=True, unique=True, primary_key=True, autoincrement=True)
    group_id = db.Column(db.Integer(), db.ForeignKey('cve_group.id', ondelete="CASCADE"), nullable=False)
    cve_id = db.Column(db.String(15), db.ForeignKey('cve.id', ondelete="CASCADE"), nullable=False)

    group = db.relationship("CVEGroup", back_populates="issues")
    cve = db.relationship("CVE")

    __table_args__ = (db.Index('cve_group_entry__group_cve_idx', group_id, cve_id, unique=True),)

    def __repr__(self):
        return '<CVEGroupEntry %r from %r referencing %r>' % (self.id, self.group_id, self.cve_id)
