# coding=utf-8
from .utils import LazyUser


def eval_url(url):
    if callable(url):
        url = url()
    return url


def setup_for_flask(auth, app, views=True, send_email=None, render=None):
    from flask import g, request, session, render_template

    auth.request = request
    auth.session = session
    if send_email:
        auth.send_email = send_email

    if render == True:  # noqa
        auth.render = render_template
    elif render:
        auth.render = render

    def set_user():
        # By doing this, ``g`` now has a ``user`` attribute that it's
        # replaced by the real user object the first time is used.
        LazyUser(auth, g)

    app.before_request_funcs.setdefault(None, []).insert(0, set_user)
    app.jinja_env.globals['csrf_token'] = auth.get_csrf_token
    app.jinja_env.globals['auth'] = auth

    if views:
        assert auth.render
        setup_for_flask_views(auth, app)


def setup_for_flask_views(auth, app):
    if 'sign_in' in auth.views:
        url_sign_in = eval_url(auth.url_sign_in)
        app.route(url_sign_in, methods=['GET', 'POST'])(auth.auth_sign_in)

    if 'sign_out' in auth.views:
        url_sign_out = eval_url(auth.url_sign_out)
        app.route(url_sign_out, methods=['GET', 'POST'])(auth.auth_sign_out)

    if 'change_password' in auth.views:
        url_change_password = eval_url(auth.url_change_password)
        app.route(url_change_password,
                  methods=['GET', 'POST'])(auth.auth_change_password)

    if 'reset_password' in auth.views:
        url_reset_password = eval_url(auth.url_reset_password)
        app.route(url_reset_password,
                  methods=['GET', 'POST'])(auth.auth_reset_password)
        app.route(url_reset_password.rstrip('/') + '/<token>/',
                  methods=['GET', 'POST'])(auth.auth_reset_password)


def setup_for_shake(auth, app, views=True, send_email=None, render=None):  # pragma: no cover
    if send_email:
        auth.send_email = send_email

    if render == True:  # noqa
        auth.render = app.render
    elif render:
        auth.render = render

    def set_user(request, **kwargs):
        auth.session = request.session
        # By doing this, `request` now has a `user` attribute that it'll be
        # replaced by the real user object the first time is used.
        LazyUser(auth, request)

    app.before_request_funcs.insert(0, set_user)
    app.render.env.globals['csrf_token'] = auth.get_csrf_token
    app.render.env.globals['auth'] = auth

    if views:
        assert auth.render
        setup_for_shake_views(auth, app)


def setup_for_shake_views(auth, app):  # pragma: no cover
    if 'sign_in' in auth.views:
        url_sign_in = eval_url(auth.url_sign_in)
        app.route(url_sign_in, methods=['GET', 'POST'])(auth.auth_sign_in)

    if 'sign_out' in auth.views:
        url_sign_out = eval_url(auth.url_sign_out)
        app.route(url_sign_out, methods=['GET', 'POST'])(auth.auth_sign_out)

    if 'change_password' in auth.views:
        url_change_password = eval_url(auth.url_change_password)
        app.route(url_change_password,
                  methods=['GET', 'POST'])(auth.auth_change_password)

    if 'reset_password' in auth.views:
        url_reset_password = eval_url(auth.url_reset_password)
        app.route(url_reset_password,
                  methods=['GET', 'POST'])(auth.auth_reset_password)
        app.route(url_reset_password.rstrip('/') + '/<token>/',
                  methods=['GET', 'POST'])(auth.auth_reset_password)
