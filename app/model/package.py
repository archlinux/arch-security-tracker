from app import db
from pyalpm import vercmp
from app.util import cmp_to_key
from operator import attrgetter


class Package(db.Model):
    __tablename__ = 'package'
    id = db.Column(db.Integer(), index=True, unique=True, primary_key=True, autoincrement=True)
    name = db.Column(db.String(96), index=True, nullable=False)
    base = db.Column(db.String(96), index=True, nullable=False)
    version = db.Column(db.String(64), nullable=False)
    arch = db.Column(db.String(16), index=True, nullable=False)
    database = db.Column(db.String(32), index=True, nullable=False)
    description = db.Column(db.String(256), nullable=False)
    url = db.Column(db.String(192))
    filename = db.Column(db.String(128), nullable=False)
    md5sum = db.Column(db.String(32), nullable=False)
    sha256sum = db.Column(db.String(64), nullable=False)
    builddate = db.Column(db.Integer(), nullable=False)

    def __repr__(self):
        return '<pkgname: {}-{}>'.format(self.name, self.version)


def filter_duplicate_packages(packages, filter_arch=False):
    filtered = []
    for pkg in packages:
        contains = False
        for f in filtered:
            if f.version != pkg.version or f.database != pkg.database:
                continue
            if not filter_arch and f.arch != pkg.arch:
                continue
            contains = True
            break
        if not contains:
            filtered.append(pkg)
    return filtered


def sort_packages(packages):
    packages = sorted(packages, key=lambda item: item.arch, reverse=True)
    packages = sorted(packages, key=lambda item: item.database)
    packages = sorted(packages, key=cmp_to_key(vercmp, attrgetter('version')), reverse=True)
    return packages
