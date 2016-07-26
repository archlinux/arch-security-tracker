from app.model.enum import Affected, Status
from app.pacman import get_pkg


def status_to_affected(status):
    if Status.unknown == status:
        return Affected.unknown
    if Status.not_affected == status:
        return Affected.not_affected
    return Affected.affected


def affected_to_status(affected, pkgname, fixed_version):
    # early exit if unknown or not affected
    if Affected.not_affected == affected:
        return Status.not_affected
    if Affected.unknown == affected:
        return Status.unknown
    versions = get_pkg(pkgname, filter_arch=True)
    # unknown if no version was found
    if not versions:
        return Status.Unknown
    version = versions[0]
    # vulnerable if the latest version is still affected
    if not fixed_version or version.version < fixed_version:
        return Status.vulnerable
    # check if any non-testing versions are fixed
    non_testing = list(filter(lambda e: 'testing' not in e.db.name, versions))
    latest_non_testing = non_testing[0]
    if latest_non_testing.version >= fixed_version:
        return Status.fixed
    # check if latest version is testing
    if 'testing' in version.db.name:
        return Status.testing
    # return vulnerable otherwise
    return Status.vulnerable
