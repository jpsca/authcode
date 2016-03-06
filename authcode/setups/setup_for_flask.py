# coding=utf-8
from ..utils import LazyUser, eval_url


def setup_for_flask(
        auth, app, send_email=None, render=None,
        session=None, request=None, urloptions=None):
    import flask

    auth.request = request or flask.request
    if session is not None:
        auth.session = session
    else:
        auth.session = flask.session
    if send_email:
        auth.send_email = send_email

    auth.render = render or flask.render_template
    app.jinja_env.globals['csrf_token'] = auth.get_csrf_token
    app.jinja_env.globals['auth'] = auth

    def set_user():
        # By doing this, ``g`` now has a ``user`` attribute that it's
        # replaced by the real user object the first time is used.
        LazyUser(auth, flask.g, user_name=auth.user_name)

    app.before_request_funcs.setdefault(None, []).insert(0, set_user)

    if auth.views:
        assert auth.render
        setup_for_flask_views(auth, app, urloptions)


def setup_for_flask_views(auth, app, urloptions):
    urloptions = urloptions or {}

    if 'sign_in' in auth.views:
        url_sign_in = eval_url(auth.url_sign_in)
        app.route(
            url_sign_in,
            methods=['GET', 'POST'],
            endpoint='{prefix}{name}'.format(
                prefix=auth.views_prefix, name='auth_sign_in'),
            **urloptions
        )(auth.auth_sign_in)

    if 'sign_out' in auth.views:
        url_sign_out = eval_url(auth.url_sign_out)
        app.route(
            url_sign_out,
            methods=['GET', 'POST'],
            endpoint='{prefix}{name}'.format(
                prefix=auth.views_prefix, name='auth_sign_out'),
            **urloptions
        )(auth.auth_sign_out)

    if 'change_password' in auth.views:
        url_change_password = eval_url(auth.url_change_password)
        app.route(
            url_change_password,
            methods=['GET', 'POST'],
            endpoint='{prefix}{name}'.format(
                prefix=auth.views_prefix, name='auth_change_password'),
            **urloptions
        )(auth.auth_change_password)

    if 'reset_password' in auth.views:
        url_reset_password = eval_url(auth.url_reset_password)
        app.route(
            url_reset_password,
            methods=['GET', 'POST'],
            endpoint='{prefix}{name}'.format(
                prefix=auth.views_prefix, name='auth_reset_password'),
            **urloptions
        )(auth.auth_reset_password)
        app.route(
            url_reset_password.rstrip('/') + '/<token>/',
            methods=['GET', 'POST'],
            endpoint='{prefix}{name}'.format(
                prefix=auth.views_prefix, name='auth_reset_password'),
            **urloptions
        )(auth.auth_reset_password)
