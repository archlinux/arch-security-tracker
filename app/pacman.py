from pycman.config import init_with_config

repos = ['core', 'extra', 'community', 'multilib', 'testing', 'community-testing', 'multilib-testing']
configpath = './pacman/pacman.conf'
handle = init_with_config(configpath)
syncdbs = handle.get_syncdbs()


def update(force=False):
    for pkgdb in syncdbs:
        pkgdb.update(force)


def get_pkg(pkgname):
    results = []
    for syncdb in syncdbs:
        result = syncdb.get_pkg(pkgname)
        if result:
            results.append(result)
    return results


def search(pkgname):
    results = []
    for syncdb in syncdbs:
        result = syncdb.search(pkgname)
        if result:
            results.append(result)
    return results
