from wtforms.validators import ValidationError, URL as URLValidator
from app.pacman import get_pkg
from app.util import multiline_to_list
from app.model.cvegroup import pkgname_regex
from app.model.cve import cve_id_regex
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


class ValidIssue(object):
    def __init__(self):
        self.message = u'Invalid issue.'

    def __call__(self, form, field):
        if not match(cve_id_regex, field.data):
            raise ValidationError(self.message)


class ValidIssues(object):
    def __init__(self):
        self.message = u'Invalid issue {}.'

    def fail(self, issue):
        raise ValidationError(self.message.format(issue))

    def __call__(self, form, field):
        issues = multiline_to_list(field.data)
        for issue in issues:
            if not match(cve_id_regex, issue):
                self.fail(issue)


class ValidURLs(object):
    def __init__(self):
        self.message = u'Invalid URL {}.'
        self.regex = URLValidator().regex

    def fail(self, url):
        raise ValidationError(self.message.format(url))

    def __call__(self, form, field):
        urls = multiline_to_list(field.data)
        for url in urls:
            if not self.regex.match(url):
                self.fail(url)
