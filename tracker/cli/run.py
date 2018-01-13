from click import option
from flask.cli import pass_script_info

from config import FLASK_DEBUG
from config import FLASK_HOST
from config import FLASK_PORT
from config import set_debug_flag

from .util import cli


@cli.command('run', short_help='Runs a development server.')
@option('--host', '-h', default=FLASK_HOST,
        help='The interface to bind to.')
@option('--port', '-p', default=FLASK_PORT,
        help='The port to bind to.')
@option('--debug/--no-debug', default=FLASK_DEBUG,
        help='Enable or disable the debug mode.  By default the debug '
        'mode enables the reloader and debugger.')
@option('--reload/--no-reload', default=None,
        help='Enable or disable the reloader.  By default the reloader '
        'is active if debug is enabled.')
@option('--debugger/--no-debugger', default=None,
        help='Enable or disable the debugger.  By default the debugger '
        'is active if debug is enabled.')
@option('--eager-loading/--lazy-loader', default=None,
        help='Enable or disable eager loading.  By default eager '
        'loading is enabled if the reloader is disabled.')
@option('--with-threads/--without-threads', default=False,
        help='Enable or disable multithreading.')
@pass_script_info
def run(info, host, port, debug, reload, debugger, eager_loading, with_threads):
    """Runs a local development server for the Flask application.

    This local server is recommended for development purposes only but it
    can also be used for simple intranet deployments.  By default it will
    not support any sort of concurrency at all to simplify debugging.  This
    can be changed with the --with-threads option which will enable basic
    multithreading.

    The reloader and debugger are by default enabled if the debug flag of
    Flask is enabled and disabled otherwise.
    """
    from werkzeug.serving import run_simple
    import os
    from flask.cli import DispatchingApp

    if debug != FLASK_DEBUG:
        set_debug_flag(debug)
    if reload is None:
        reload = bool(debug)
    if debugger is None:
        debugger = bool(debug)
    if eager_loading is None:
        eager_loading = not reload

    app = DispatchingApp(info.load_app, use_eager_loading=eager_loading)

    # Extra startup messages.  This depends a bit on Werkzeug internals to
    # not double execute when the reloader kicks in.
    if os.environ.get('WERKZEUG_RUN_MAIN') != 'true':
        # If we have an import path we can print it out now which can help
        # people understand what's being served.  If we do not have an
        # import path because the app was loaded through a callback then
        # we won't print anything.
        if info.app_import_path is not None:
            print(' * Serving Flask app "{}"'.format(info.app_import_path))
        if debug is not None:
            print(' * Forcing debug mode {}'.format(debug and 'on' or 'off'))

    run_simple(host, port, app, use_reloader=reload, use_debugger=debugger, threaded=with_threads)
