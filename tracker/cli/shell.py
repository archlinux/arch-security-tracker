from click import UNPROCESSED
from click import argument
from flask.cli import with_appcontext

from .util import cli


@cli.command(context_settings=dict(ignore_unknown_options=True))
@argument('ipython_args', nargs=-1, type=UNPROCESSED)
@with_appcontext
def shell(ipython_args):
    """Runs a shell in the app context.
    Runs an interactive Python shell in the context of a given
    Flask application. The application will populate the default
    namespace of this shell according to it's configuration.
    This is useful for executing small snippets of management code
    without having to manually configuring the application.
    """

    from sys import version, platform
    from flask.globals import _app_ctx_stack
    app = _app_ctx_stack.top.app
    ctx = app.make_shell_context()

    try:
        from IPython import __version__ as ipython_version, start_ipython
        from IPython.terminal.ipapp import load_default_config
        from traitlets.config.loader import Config

        if 'IPYTHON_CONFIG' in app.config:
            config = Config(app.config['IPYTHON_CONFIG'])
        else:
            config = load_default_config()

        config.TerminalInteractiveShell.banner1 = '''Python {} on {}
    IPython: {}
    App: {}{}
    Instance: {}'''.format(version,
                           platform,
                           ipython_version,
                           app.import_name,
                           app.debug and ' [debug]' or '',
                           app.instance_path)
        start_ipython(
            argv=ipython_args,
            user_ns=ctx,
            config=config,
        )
    except ImportError:
        # fallback to standard python interactive console
        from code import interact

        banner = '''Python {} on {}
    App: {}{}
    Instance: {}'''.format(version,
                           platform,
                           app.import_name,
                           app.debug and ' [debug]' or '',
                           app.instance_path)
        interact(local=ctx, banner=banner)
