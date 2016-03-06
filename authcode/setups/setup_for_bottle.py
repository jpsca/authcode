# coding=utf-8
from ..utils import LazyUser, eval_url


def setup_for_bottle(
        auth, app, send_email=None, render=None,
        session=None, request=None, urloptions=None):
    import bottle

    auth.request = request or bottle.request
    if session is not None:
        auth.session = session
    if send_email:
        auth.send_email = send_email

    auth.render = render or bottle.template
    bottle.BaseTemplate.defaults['csrf_token'] = auth.get_csrf_token
    bottle.BaseTemplate.defaults['auth'] = auth

    """
    Set the session **before** calling ``setup_for_bottle`` like this:

        @hook('before_request')
        def setup_request():
            request.session = request.environ['beaker.session']
    """

    @bottle.hook('before_request')
    def after_request():
        auth.session = session or getattr(bottle.request, 'session') \
            or bottle.request.environ.get('beaker.session')
        assert auth.session, 'Session not found'

        # By doing this, ``bottle.request`` now has a ``user`` attribute
        # that it's replaced by the real user object the first time is used.
        LazyUser(auth, bottle.request, user_name=auth.user_name)

    if auth.views:
        assert auth.render
        setup_for_bottle_views(auth, app, urloptions)


def setup_for_bottle_views(auth, app, urloptions):
    urloptions = urloptions or {}

    if 'sign_in' in auth.views:
        url_sign_in = eval_url(auth.url_sign_in)
        app.route(
            url_sign_in,
            method=['GET', 'POST'],
            name='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_sign_in'
            ),
            callback=auth.auth_sign_in,
            **urloptions
        )

    if 'sign_out' in auth.views:
        url_sign_out = eval_url(auth.url_sign_out)
        app.route(
            url_sign_out,
            method=['GET', 'POST'],
            name='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_sign_out'
            ),
            callback=auth.auth_sign_out,
            **urloptions
        )

    if 'change_password' in auth.views:
        url_change_password = eval_url(auth.url_change_password)
        app.route(
            url_change_password,
            method=['GET', 'POST'],
            name='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_change_password'
            ),
            callback=auth.auth_change_password,
            **urloptions
        )

    if 'reset_password' in auth.views:
        url_reset_password = eval_url(auth.url_reset_password)
        app.route(
            url_reset_password,
            method=['GET', 'POST'],
            name='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_reset_password'
            ),
            callback=auth.auth_reset_password,
            **urloptions
        )
        app.route(
            url_reset_password.rstrip('/') + '/<token>/',
            method=['GET', 'POST'],
            name='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_reset_password'
            ),
            callback=auth.auth_reset_password,
            **urloptions
        )
