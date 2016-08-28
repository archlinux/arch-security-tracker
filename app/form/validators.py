from wtforms.validators import ValidationError
from app.pacman import get_pkg
from app.util import multiline_to_list
from app.model.cvegroup import pkgname_regex
from pyalpm import vercmp
from re import match


class ValidPackageName(object):
    def __init__(self):
        self.message = u'Unknown package.'

    def __call__(self, form, field):
        if not match(pkgname_regex, field.data):
            self.fail(field.data)
        versions = get_pkg(field.data)
        if not versions:
            raise ValidationError(self.message)


class ValidPackageNames(object):
    def __init__(self):
        self.message = u'Unknown package {}.'

    def fail(self, pkgname):
        raise ValidationError(self.message.format(pkgname))

    def __call__(self, form, field):
        pkgnames = multiline_to_list(field.data)
        for pkgname in pkgnames:
            if not match(pkgname_regex, pkgname):
                self.fail(pkgname)
            versions = get_pkg(pkgname)
            if not versions:
                self.fail(pkgname)


class SamePackageVersions(object):
    def __init__(self):
        self.message = u'Mismatching version {}.'

    def fail(self, pkgname):
        raise ValidationError(self.message.format(pkgname))

    def __call__(self, form, field):
        pkgnames = multiline_to_list(field.data)
        ref_version = None
        for pkgname in pkgnames:
            versions = get_pkg(pkgname)
            if not versions:
                self.fail(pkgname)
            ref_version = ref_version if ref_version else versions[0]
            if 0 != vercmp(ref_version.version, versions[0].version):
                self.fail(pkgname)
