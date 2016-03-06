# coding=utf-8
from ..utils import LazyUser, eval_url


def setup_for_shake(
        auth, app, send_email=None, render=None,
        session=None, request=None, urloptions=None):  # pragma: no cover (deprecated)
    if send_email:
        auth.send_email = send_email

    auth.request = request
    auth.render = render or app.render

    def set_user(_request, **kwargs):
        _request = request or _request
        auth.request = _request
        auth.session = session or _request.session
        LazyUser(auth, _request, user_name=auth.user_name)

    app.before_request_funcs.insert(0, set_user)
    app.render.env.globals['csrf_token'] = auth.get_csrf_token
    app.render.env.globals['auth'] = auth

    if auth.views:
        assert auth.render
        setup_for_shake_views(auth, app, urloptions)


def setup_for_shake_views(auth, app, urloptions):  # pragma: no cover (deprecated)
    urloptions = urloptions or {}

    if 'sign_in' in auth.views:
        url_sign_in = eval_url(auth.url_sign_in)
        app.route(
            url_sign_in,
            methods=['GET', 'POST'],
            name='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_sign_in'
            ), **urloptions
        )(auth.auth_sign_in)

    if 'sign_out' in auth.views:
        url_sign_out = eval_url(auth.url_sign_out)
        app.route(
            url_sign_out,
            methods=['GET', 'POST'],
            name='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_sign_out'
            ), **urloptions
        )(auth.auth_sign_out)

    if 'change_password' in auth.views:
        url_change_password = eval_url(auth.url_change_password)
        app.route(
            url_change_password,
            methods=['GET', 'POST'],
            name='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_change_password'
            ), **urloptions
        )(auth.auth_change_password)

    if 'reset_password' in auth.views:
        url_reset_password = eval_url(auth.url_reset_password)
        app.route(
            url_reset_password,
            methods=['GET', 'POST'],
            name='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_reset_password'
            ), **urloptions
        )(auth.auth_reset_password)
        app.route(
            url_reset_password.rstrip('/') + '/<token>/',
            methods=['GET', 'POST'],
            name='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_reset_password'
            ), **urloptions
        )(auth.auth_reset_password)
