# coding=utf-8
from __future__ import print_function

import authcode
from authcode import wsgi
import pytest

from helpers import SECRET_KEY


def test_setup_for_webpy_incomplete():
    web = pytest.importorskip("web")

    urls = (
        '/', 'index',
    )

    class index:
        def GET(self):
            return "Hello, world!"

    app = web.application(urls, globals())

    auth = authcode.Auth(SECRET_KEY, wsgi=wsgi.webpy)
    authcode.setup_for_webpy(auth, app)


def test_setup_for_webpy_complete():
    web = pytest.importorskip("web")

    urls = (
        '/', 'index',
    )

    class index:
        def GET(self):
            return "Hello, world!"

    app = web.application(urls, globals())
    render = web.template.render('templates/')
    session = {}

    def send_email(user, subject, msg):
        pass

    auth = authcode.Auth(SECRET_KEY, wsgi=wsgi.webpy)
    authcode.setup_for_webpy(
        auth, app,
        render=render, session=session, send_email=send_email
    )

    assert auth.render == render
    assert 'auth' in render._keywords['globals'].values()
    assert 'csrf_token' in render._keywords['globals'].values()
    assert auth.session == session
    assert auth.send_email == send_email

    mapping = dict(app.mapping)
    assert mapping['/sign-in/'].__name__ == 'auth_sign_in'
    assert mapping['/sign-out/'].__name__ == 'auth_sign_out'
    assert mapping['/change-password/'].__name__ == 'auth_change_password'
    assert mapping['/reset-password/'].__name__ == 'auth_reset_password'
    assert mapping['/reset-password/([azAZ09]+)/'].__name__ == 'auth_reset_password_token'


def test_setup_for_webpy_noviews():
    web = pytest.importorskip("web")

    urls = (
        '/', 'index',
    )

    class index:
        def GET(self):
            return "Hello, world!"

    app = web.application(urls, globals())
    auth = authcode.Auth(SECRET_KEY, wsgi=wsgi.webpy, views=[])
    authcode.setup_for_webpy(auth, app)
    mapping = dict(app.mapping)

    assert mapping.keys() == ['/']


def test_setup_for_webpy_partialviews():
    web = pytest.importorskip("web")

    urls = (
        '/', 'index',
    )

    class index:
        def GET(self):
            return "Hello, world!"

    app = web.application(urls, globals())
    auth = authcode.Auth(SECRET_KEY, wsgi=wsgi.webpy, views=['sign_in'])
    authcode.setup_for_webpy(auth, app)
    mapping = dict(app.mapping)

    assert sorted(mapping.keys()) == ['/', '/sign-in/']

    app = web.application(urls, globals())
    auth = authcode.Auth(SECRET_KEY, wsgi=wsgi.webpy, views=['change_password'])
    authcode.setup_for_webpy(auth, app)
    mapping = dict(app.mapping)

    assert sorted(mapping.keys()) == ['/', '/change-password/']


def test_setup_for_webpy_other_render():
    web = pytest.importorskip("web")

    urls = (
        '/', 'index',
    )

    class index:
        def GET(self):
            return "Hello, world!"

    def render(tmpl, **context):
        pass

    app = web.application(urls, globals())
    auth = authcode.Auth(SECRET_KEY, wsgi=wsgi.webpy)
    authcode.setup_for_webpy(auth, app, render=render)

    assert auth.render == render
