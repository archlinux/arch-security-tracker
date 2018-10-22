from tracker import db


class CVEGroupPackage(db.Model):

    __versioned__ = {}
    __tablename__ = 'cve_group_package'

    id = db.Column(db.Integer(), index=True, unique=True, primary_key=True, autoincrement=True)
    group_id = db.Column(db.Integer(), db.ForeignKey('cve_group.id', ondelete="CASCADE"), nullable=False)
    pkgname = db.Column(db.String(64), nullable=False)

    group = db.relationship("CVEGroup", back_populates="packages")

    __table_args__ = (db.Index('cve_group_package__group_pkgname_idx', group_id, pkgname, unique=True),)

    def __repr__(self):
        return '<CVEGroupPackage %r from %r referencing %r>' % (self.id, self.group_id, self.pkgname)
