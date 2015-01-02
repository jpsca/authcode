# coding=utf-8
from ..utils import LazyUser


def setup_for_cherrypy(
        auth, send_email=None, render=None, session=None, request=None):
    import cherrypy

    auth.request = request or cherrypy.request
    if send_email:
        auth.send_email = send_email
    if render:
        auth.render = render

    def set_user_and_session():
        auth.session = session or cherrypy.session
        # By doing this, ``cherrypy.request`` now has a ``user`` attribute
        # that it's replaced by the real user object the first time is used.
        LazyUser(auth, cherrypy.request, user_name=auth.user_name)

    cherrypy.request.hooks.attach('before_handler', set_user_and_session)

    cherrypy.tools.protected = cherrypy.Tool(
        'before_handler', auth.tool_protected, name='protected')

    if auth.views:
        assert auth.render
        setup_for_cherrypy_views(auth)


def setup_for_cherrypy_views(auth, map=None):
    # INCOMPLETE
    #! TODO: Use auth.url_sign_in, etc. or find a workaround

    import cherrypy

    if 'sign_in' in auth.views:
        cherrypy.expose(
            # __func__ is to make the auth methods exposable in Python 2.*
            # Otherwise it raises a
            # ``'instancemethod' object has no attribute 'exposed'`` error
            auth.auth_sign_in.__func__,
            alias='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_sign_in'
            )
        )

    if 'sign_out' in auth.views:
        cherrypy.expose(
            # __func__ is to make the auth methods exposable in Python 2.*
            # Otherwise it raises a
            # ``'instancemethod' object has no attribute 'exposed'`` error
            auth.auth_sign_out.__func__,
            alias='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_sign_out'
            )
        )

    if 'change_password' in auth.views:
        cherrypy.expose(
            # __func__ is to make the auth methods exposable in Python 2.*
            # Otherwise it raises a
            # ``'instancemethod' object has no attribute 'exposed'`` error
            auth.auth_change_password.__func__,
            alias='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_change_password'
            )
        )

    if 'reset_password' in auth.views:
        cherrypy.expose(
            # __func__ is to make the auth methods exposable in Python 2.*
            # Otherwise it raises a
            # ``'instancemethod' object has no attribute 'exposed'`` error
            auth.auth_reset_password.__func__,
            alias='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_reset_password'
            )
        )
        cherrypy.expose(
            # __func__ is to make the auth methods exposable in Python 2.*
            # Otherwise it raises a
            # ``'instancemethod' object has no attribute 'exposed'`` error
            auth.auth_reset_password.__func__,
            alias='{prefix}{name}'.format(
                prefix=auth.views_prefix,
                name='auth_reset_password_token'
            )
        )
