from wtforms.validators import ValidationError
from app.pacman import get_pkg
from app.util import multiline_to_list
from pyalpm import vercmp


class ValidPackageName(object):
    def __init__(self):
        self.message = u'Unknown package.'

    def __call__(self, form, field):
        versions = get_pkg(field.data)
        if not versions:
            raise ValidationError(self.message)


class ValidPackageNames(object):
    def __init__(self):
        self.message = u'Unknown package {}.'

    def __call__(self, form, field):
        pkgnames = multiline_to_list(field.data)
        for pkgname in pkgnames:
            versions = get_pkg(pkgname)
            if not versions:
                raise ValidationError(self.message.format(pkgname))


class SamePackageVersions(object):
    def __init__(self):
        self.message = u'Mismatching version {}.'

    def __call__(self, form, field):
        pkgnames = multiline_to_list(field.data)
        ref_version = None
        for pkgname in pkgnames:
            versions = get_pkg(pkgname)
            if not versions:
                raise ValidationError(self.message.format(pkgname))
            ref_version = ref_version if ref_version else versions[0]
            if 0 != vercmp(ref_version.version, versions[0].version):
                raise ValidationError(self.message.format(pkgname))
