# coding=utf-8
from __future__ import print_function

import authcode
import pytest

from helpers import SECRET_KEY


def test_setup_for_cherrypy():
    cherrypy = pytest.importorskip("cherrypy")

    auth = authcode.Auth(SECRET_KEY)
    authcode.setup_for_cherrypy(auth)

    assert auth.request == cherrypy.request
    assert cherrypy.tools.protected


def test_setup_for_cherrypy_custom_render():
    cherrypy = pytest.importorskip("cherrypy")

    def send_email(user, subject, msg):
        pass

    def render(tmpl, **kwargs):
        pass

    auth = authcode.Auth(SECRET_KEY)
    authcode.setup_for_cherrypy(auth, render=render, send_email=send_email)

    assert auth.render == render
    assert auth.send_email == send_email
    assert auth.request == cherrypy.request
    assert cherrypy.tools.protected
