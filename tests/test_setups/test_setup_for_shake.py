# coding=utf-8
from __future__ import print_function

import authcode
import pytest
from sqlalchemy_wrapper import SQLAlchemy

from helpers import SECRET_KEY


def test_setup_for_shake():
    shake = pytest.importorskip("shake")
    app = shake.Shake(__file__, {})
    db = SQLAlchemy('sqlite:///', app)
    auth = authcode.Auth(SECRET_KEY, db=db)
    authcode.setup_for_shake(auth, app)
    assert auth.render == app.render


def test_setup_shake_custom():
    shake = pytest.importorskip("shake")

    app = shake.Shake(__file__, {})
    db = SQLAlchemy('sqlite:///', app)
    auth = authcode.Auth(SECRET_KEY, db=db)

    def send_email(user, subject, msg):
        pass

    class Env(object):
        globals = {}

    class Render(object):
        env = Env()

    class Session(object):
        pass

    render = Render()
    session = Session()

    authcode.setup_for_shake(
        auth, app,
        send_email=send_email, render=render, session=session
    )
    assert auth.send_email == send_email
    assert auth.render == render
    assert app.render.env.globals['csrf_token']
    assert app.render.env.globals['auth']


def test_setup_shake_render():
    shake = pytest.importorskip("shake")

    app = shake.Shake(__file__, {})
    db = SQLAlchemy('sqlite:///', app)
    auth = authcode.Auth(SECRET_KEY, db=db)

    authcode.setup_for_shake(auth, app)
    assert auth.send_email
    assert auth.render == app.render
    assert app.render.env.globals['csrf_token']
    assert app.render.env.globals['auth']


def test_setup_shake_false_render():
    shake = pytest.importorskip("shake")

    app = shake.Shake(__file__, {})
    db = SQLAlchemy('sqlite:///', app)
    auth = authcode.Auth(SECRET_KEY, db=db)

    authcode.setup_for_shake(auth, app, render=None)
    assert auth.send_email
    assert auth.render == app.render
    assert app.render.env.globals['csrf_token']
    assert app.render.env.globals['auth']


def test_setup_shake_no_views():
    shake = pytest.importorskip("shake")

    app = shake.Shake(__file__, {})
    db = SQLAlchemy('sqlite:///', app)
    auth = authcode.Auth(SECRET_KEY, db=db, views=[])

    authcode.setup_for_shake(auth, app)
    assert len(app.url_map._rules) == 0


def test_setup_shake_default_views():
    shake = pytest.importorskip("shake")

    app = shake.Shake(__file__, {})
    db = SQLAlchemy('sqlite:///', app)
    auth = authcode.Auth(SECRET_KEY, db=db)

    authcode.setup_for_shake(auth, app)
    assert len(app.url_map._rules) == 5


def test_setup_shake_views_urls():
    shake = pytest.importorskip("shake")

    app = shake.Shake(__file__, {})
    db = SQLAlchemy('sqlite:///', app)
    config = {
        'url_sign_in': '/ingresar/',
        'url_sign_out': '/salir/',
        'url_reset_password': '/restablecer-contrasena/',
        'url_change_password': '/cambiar-contrasena/',
    }
    auth = authcode.Auth(SECRET_KEY, db=db, **config)

    authcode.setup_for_shake(auth, app)
    rules = app.url_map._rules
    endpoints = dict([(ru.endpoint.__name__, ru.rule) for ru in rules])

    assert endpoints['auth_sign_in'] == config['url_sign_in']
    assert endpoints['auth_sign_out'] == config['url_sign_out']
    assert endpoints['auth_change_password'] == config['url_change_password']
    assert endpoints['auth_reset_password'] == config['url_reset_password'] + '<token>/'


def test_setup_shake_views_callable_urls():
    shake = pytest.importorskip("shake")

    app = shake.Shake(__file__, {})
    db = SQLAlchemy('sqlite:///', app)
    config = {
        'url_sign_in': lambda: '/my-login',
        'url_reset_password': lambda: '/reset-secret',
    }
    auth = authcode.Auth(SECRET_KEY, db=db, **config)

    authcode.setup_for_shake(auth, app)
    rules = app.url_map._rules
    endpoints = dict([(ru.endpoint.__name__, ru.rule) for ru in rules])

    assert endpoints['auth_sign_in'] == '/my-login'
    assert endpoints['auth_reset_password'] == '/reset-secret/<token>/'
