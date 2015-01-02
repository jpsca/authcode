# coding=utf-8
from ..utils import LazyUser, eval_url


def setup_for_webpy(
        auth, app, send_email=None, render=None, session=None, request=None):
    import web

    if send_email:
        auth.send_email = send_email

    if render:
        render._add_global('csrf_token', auth.get_csrf_token)
        render._add_global('auth', auth)
        auth.render = render

    if session:
        auth.session = session

    def set_user():
        # By doing this, ``web.ctx`` now has a ``user`` attribute that it's
        # replaced by the real user object the first time is used.
        LazyUser(auth, web.ctx, user_name=auth.user_name)

    app.processors.insert(0, web.loadhook(set_user))

    if auth.views:
        assert auth.render
        setup_for_webpy_views(auth, app)


def setup_for_webpy_views(auth, app):
    if 'sign_in' in auth.views:
        url_sign_in = eval_url(auth.url_sign_in)
        name = '{prefix}{name}'.format(
            prefix=auth.views_prefix,
            name='auth_sign_in'
        )
        app.add_mapping(
            url_sign_in,
            make_class_view(name, auth.auth_sign_in)
        )

    if 'sign_out' in auth.views:
        url_sign_out = eval_url(auth.url_sign_out)
        name = '{prefix}{name}'.format(
            prefix=auth.views_prefix,
            name='auth_sign_out'
        )
        app.add_mapping(
            url_sign_out,
            make_class_view(name, auth.auth_sign_out)
        )

    if 'change_password' in auth.views:
        url_change_password = eval_url(auth.url_change_password)
        name = '{prefix}{name}'.format(
            prefix=auth.views_prefix,
            name='auth_change_password'
        )
        app.add_mapping(
            url_change_password,
            make_class_view(name, auth.auth_change_password)
        )

    if 'reset_password' in auth.views:
        url_reset_password = eval_url(auth.url_reset_password)
        name = '{prefix}{name}'.format(
            prefix=auth.views_prefix,
            name='auth_reset_password'
        )
        app.add_mapping(
            url_reset_password,
            make_class_view(name, auth.auth_reset_password)
        )

        url_reset_password_token = (
            url_reset_password.rstrip('/') +
            '/([azAZ09]+)/'
        )
        name = '{prefix}{name}'.format(
            prefix=auth.views_prefix,
            name='auth_reset_password_token'
        )
        app.add_mapping(
            url_reset_password_token,
            make_class_view(name, auth.auth_reset_password)
        )


def make_class_view(class_name, endpoint):
    attrs = {
        'GET': endpoint,
        'POST': endpoint,
    }
    return type(class_name, (object,), attrs)
