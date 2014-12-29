# coding=utf-8
from .utils import LazyUser


def eval_url(url):
    if callable(url):
        url = url()
    return url


def setup_for_flask(
        auth, app, send_email=None,
        render=None, session=None, request=None):
    import flask

    auth.request = request or flask.request
    auth.session = session or flask.session
    if send_email:
        auth.send_email = send_email

    auth.render = render or flask.render_template

    def set_user():
        # By doing this, ``g`` now has a ``user`` attribute that it's
        # replaced by the real user object the first time is used.
        LazyUser(auth, flask.g, user_name=auth.user_name)

    app.before_request_funcs.setdefault(None, []).insert(0, set_user)
    app.jinja_env.globals['csrf_token'] = auth.get_csrf_token
    app.jinja_env.globals['auth'] = auth

    if auth.views:
        assert auth.render
        setup_for_flask_views(auth, app)


def setup_for_flask_views(auth, app):
    if 'sign_in' in auth.views:
        url_sign_in = eval_url(auth.url_sign_in)
        app.route(
            url_sign_in,
            methods=['GET', 'POST'],
            endpoint='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_sign_in'
            )
        )(auth.auth_sign_in)

    if 'sign_out' in auth.views:
        url_sign_out = eval_url(auth.url_sign_out)
        app.route(
            url_sign_out,
            methods=['GET', 'POST'],
            endpoint='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_sign_out'
            )
        )(auth.auth_sign_out)

    if 'change_password' in auth.views:
        url_change_password = eval_url(auth.url_change_password)
        app.route(
            url_change_password,
            methods=['GET', 'POST'],
            endpoint='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_change_password'
            )
        )(auth.auth_change_password)

    if 'reset_password' in auth.views:
        url_reset_password = eval_url(auth.url_reset_password)
        app.route(
            url_reset_password,
            methods=['GET', 'POST'],
            endpoint='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_reset_password'
            )
        )(auth.auth_reset_password)
        app.route(
            url_reset_password.rstrip('/') + '/<token>/',
            methods=['GET', 'POST'],
            endpoint='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_reset_password'
            )
        )(auth.auth_reset_password)


def setup_for_shake(
        auth, app, send_email=None,
        render=None, session=None, request=None):  # pragma: no cover (deprecated)
    if send_email:
        auth.send_email = send_email

    auth.render = render or app.render

    def set_user_shake(_request, **kwargs):
        auth.session = session or _request.session
        LazyUser(auth, request or _request, user_name=auth.user_name)

    app.before_request_funcs.insert(0, set_user_shake)
    app.render.env.globals['csrf_token'] = auth.get_csrf_token
    app.render.env.globals['auth'] = auth

    if auth.views:
        assert auth.render
        setup_for_shake_views(auth, app)


def setup_for_shake_views(auth, app):  # pragma: no cover (deprecated)
    if 'sign_in' in auth.views:
        url_sign_in = eval_url(auth.url_sign_in)
        app.route(
            url_sign_in,
            methods=['GET', 'POST'],
            name='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_sign_in'
            )
        )(auth.auth_sign_in)

    if 'sign_out' in auth.views:
        url_sign_out = eval_url(auth.url_sign_out)
        app.route(
            url_sign_out,
            methods=['GET', 'POST'],
            name='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_sign_out'
            )
        )(auth.auth_sign_out)

    if 'change_password' in auth.views:
        url_change_password = eval_url(auth.url_change_password)
        app.route(
            url_change_password,
            methods=['GET', 'POST'],
            name='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_change_password'
            )
        )(auth.auth_change_password)

    if 'reset_password' in auth.views:
        url_reset_password = eval_url(auth.url_reset_password)
        app.route(
            url_reset_password,
            methods=['GET', 'POST'],
            name='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_reset_password'
            )
        )(auth.auth_reset_password)
        app.route(
            url_reset_password.rstrip('/') + '/<token>/',
            methods=['GET', 'POST'],
            name='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_reset_password'
            )
        )(auth.auth_reset_password)
