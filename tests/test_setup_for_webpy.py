# coding=utf-8
from __future__ import print_function

import authcode
from authcode import wsgi
import pytest

from helpers import SECRET_KEY


def test_setup_for_webpy():
    web = pytest.importorskip("web")

    urls = (
        '/', 'index',
    )

    class index:
        def GET(self):
            return "Hello, world!"

    app = web.application(urls, globals())
    render = web.template.render('templates/')
    auth = authcode.Auth(SECRET_KEY, wsgi=wsgi.webpy)
    authcode.setup_for_webpy(auth, app, render=render)

    assert auth.render == render
    assert 'auth' in render._keywords['globals'].values()
    assert 'csrf_token' in render._keywords['globals'].values()

    mapping = dict(app.mapping)
    assert mapping['/sign-in/'].__name__ == 'auth_sign_in'
    assert mapping['/sign-out/'].__name__ == 'auth_sign_out'
    assert mapping['/change-password/'].__name__ == 'auth_change_password'
    assert mapping['/reset-password/'].__name__ == 'auth_reset_password'
    assert mapping['/reset-password/([azAZ09]+)/'].__name__ == 'auth_reset_password_token'
