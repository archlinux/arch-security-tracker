from click import echo, option, pass_context
from . import cli


@cli.group()
def update():
    """Update the application.

    In doubt, call env as a general purpose command."""
    pass


@update.command()
@option('--force', is_flag=True, default=False, help='Force database update.')
def pacman(force):
    """Update pacman database."""

    from tracker.pacman import update as update_pacman_db

    echo('Updating pacman database...', nl=False)
    update_pacman_db(force=force)
    echo('done')


@update.command()
def cache():
    """Update package cache."""

    from tracker.maintenance import update_package_cache

    echo('Updating package cache...')
    update_package_cache()


@update.command()
@pass_context
def env(ctx):
    """Update pacman, groups and caches."""

    ctx.invoke(pacman)
    ctx.invoke(cache)
    ctx.invoke(group)


@update.command()
@option('--recalc', is_flag=True, help='Recalculate everything.')
@option('--recalc-status', is_flag=True, help='Recalculate group status.')
@option('--recalc-severity', is_flag=True, help='Recalculate group severity.')
def group(recalc=False, recalc_status=False, recalc_severity=False):
    """Update group status."""

    from tracker.maintenance import update_group_status, recalc_group_severity, recalc_group_status

    echo('Updating group status...', nl=False)
    updated = update_group_status()
    echo('done')
    for update in updated:
        group = update['group']
        old_status = update['old_status']
        echo('  -> Updated {}: {} -> {}'.format(group.name, old_status, group.status))

    if recalc or recalc_status:
        echo('Recalcing group status...', nl=False)
        updated = recalc_group_status()
        echo('done')
        for update in updated:
            group = update['group']
            old_status = update['old_status']
            echo('  -> Updated {}: {} -> {}'.format(group.name, old_status, group.status))

    if recalc or recalc_severity:
        echo('Recalcing group severity...', nl=False)
        updated = recalc_group_severity()
        echo('done')
        for update in updated:
            group = update['group']
            old_severity = update['old_severity']
            echo('  -> Updated {}: {} -> {}'.format(group.name, old_severity, group.severity))
