# coding=utf-8
from __future__ import print_function

import bottle
from bottle import Bottle
from sqlalchemy_wrapper import SQLAlchemy
import authcode

from helpers import SECRET_KEY


def test_setup_for_bottle():
    app = Bottle()
    db = SQLAlchemy('sqlite:///', app)
    auth = authcode.Auth(SECRET_KEY, db=db)
    authcode.setup_for_bottle(auth, app)

    assert auth.render == bottle.template
    assert auth.request is not None
    assert auth.request == bottle.request
    assert bottle.BaseTemplate.defaults['csrf_token']
    assert bottle.BaseTemplate.defaults['auth']


def test_setup_bottle_custom():
    app = Bottle()
    db = SQLAlchemy('sqlite:///', app)
    auth = authcode.Auth(SECRET_KEY, db=db)

    render = bottle.jinja2_template

    class CustomSession(object):
        pass
    session = CustomSession()

    def send_email(user, subject, msg):
        pass

    authcode.setup_for_bottle(
        auth, app,
        render=render, session=session, send_email=send_email
    )
    assert auth.render == render
    assert auth.send_email == send_email
    assert auth.session == session


def test_setup_bottle_no_views():
    app = Bottle()
    db = SQLAlchemy('sqlite:///', app)
    auth = authcode.Auth(SECRET_KEY, db=db, views=[])

    authcode.setup_for_bottle(auth, app)
    assert not len(app.routes)


def test_setup_bottle_partial_views_1():
    app = Bottle()
    db = SQLAlchemy('sqlite:///', app)
    auth = authcode.Auth(SECRET_KEY, db=db, views='sign_in sign_out'.split())
    authcode.setup_for_bottle(auth, app)
    names = [route.name for route in app.routes]

    assert 'auth_sign_in' in names
    assert 'auth_sign_out' in names
    assert 'auth_reset_password' not in names
    assert 'auth_change_password' not in names


def test_setup_bottle_partial_views_2():
    app = Bottle()
    db = SQLAlchemy('sqlite:///', app)
    auth = authcode.Auth(SECRET_KEY, db=db, views='change_password'.split())
    authcode.setup_for_bottle(auth, app)
    names = [route.name for route in app.routes]

    assert 'auth_sign_in' not in names
    assert 'auth_sign_out' not in names
    assert 'auth_reset_password' not in names
    assert 'auth_change_password' in names


def test_setup_bottle_views_urls():
    app = Bottle()
    db = SQLAlchemy('sqlite:///', app)
    config = {
        'url_sign_in': '/ingresar/',
        'url_sign_out': '/salir/',
        'url_reset_password': '/restablecer-contrasena/',
        'url_change_password': '/cambiar-contrasena/',
    }
    auth = authcode.Auth(SECRET_KEY, db=db, **config)

    authcode.setup_for_bottle(auth, app)
    rules = dict((route.name, route.rule) for route in app.routes)

    assert rules['auth_sign_in'] == config['url_sign_in']
    assert rules['auth_sign_out'] == config['url_sign_out']
    assert rules['auth_change_password'] == config['url_change_password']
    assert rules['auth_reset_password'] == config['url_reset_password'] + '<token>/'


def test_setup_bottle_views_callable_urls():
    app = Bottle()
    db = SQLAlchemy('sqlite:///', app)
    config = {
        'url_sign_in': lambda: '/my-login',
        'url_reset_password': lambda: '/reset-secret',
    }
    auth = authcode.Auth(SECRET_KEY, db=db, **config)

    authcode.setup_for_bottle(auth, app)
    rules = dict((route.name, route.rule) for route in app.routes)

    assert rules['auth_sign_in'] == '/my-login'
    assert rules['auth_reset_password'] == '/reset-secret/<token>/'
