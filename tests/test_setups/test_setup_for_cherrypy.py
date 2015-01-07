# coding=utf-8
from __future__ import print_function

import authcode
from authcode import wsgi
import pytest

from helpers import SECRET_KEY


def test_setup_for_cherrypy():
    cherrypy = pytest.importorskip("cherrypy")
    auth = authcode.Auth(SECRET_KEY, wsgi=wsgi.cherrypy)
    authcode.setup_for_cherrypy(auth)

    assert auth.request == cherrypy.request
    assert cherrypy.tools.protected

    cherrypy.request.hooks['before_handler'] = []


def test_setup_for_cherrypy_noviews():
    cherrypy = pytest.importorskip("cherrypy")
    auth = authcode.Auth(SECRET_KEY, wsgi=wsgi.cherrypy, views=[])
    authcode.setup_for_cherrypy(auth)

    assert auth.request == cherrypy.request
    assert cherrypy.tools.protected

    cherrypy.request.hooks['before_handler'] = []


def test_setup_for_cherrypy_partialviews():
    cherrypy = pytest.importorskip("cherrypy")
    auth = authcode.Auth(SECRET_KEY, wsgi=wsgi.cherrypy, views=['sign_in'])
    authcode.setup_for_cherrypy(auth)

    assert auth.request == cherrypy.request
    assert cherrypy.tools.protected
    # TODO: test if only the sign_in view was added

    auth = authcode.Auth(SECRET_KEY, wsgi=wsgi.cherrypy, views=['change_password'])
    authcode.setup_for_cherrypy(auth)

    assert auth.request == cherrypy.request
    assert cherrypy.tools.protected
    # TODO: test if only the sign_in view was added

    cherrypy.request.hooks['before_handler'] = []


def test_setup_for_cherrypy_custom():
    cherrypy = pytest.importorskip("cherrypy")

    def send_email(user, subject, msg):
        pass

    def render(tmpl, **kwargs):
        pass

    auth = authcode.Auth(SECRET_KEY, wsgi=wsgi.cherrypy)
    authcode.setup_for_cherrypy(auth, render=render, send_email=send_email)

    assert auth.render == render
    assert auth.send_email == send_email
    assert auth.request == cherrypy.request
    assert cherrypy.tools.protected

    cherrypy.request.hooks['before_handler'] = []
