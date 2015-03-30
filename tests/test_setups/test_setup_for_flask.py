# coding=utf-8
from __future__ import print_function

import flask
from flask import Flask
from sqlalchemy_wrapper import SQLAlchemy
import authcode

from helpers import SECRET_KEY


def test_setup_for_flask():
    app = Flask(__name__)
    db = SQLAlchemy('sqlite:///', app)
    auth = authcode.Auth(SECRET_KEY, db=db)
    authcode.setup_for_flask(auth, app)

    assert auth.render == flask.render_template
    assert auth.request.__name__ == flask.request.__name__
    assert auth.session.__name__ == flask.session.__name__
    assert app.jinja_env.globals['csrf_token']
    assert app.jinja_env.globals['auth']


def test_flask_sqlalchemy():
    from flask.ext.sqlalchemy import SQLAlchemy as FlaskSQLAlchemy

    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'
    db = FlaskSQLAlchemy(app)

    class UserMixin(object):
        email = db.Column(db.Unicode(300))

        def __init__(self, login, email):
            self.login = login
            self.email = email
            self.password = 'foobar'

    class RoleMixin(object):
        description = db.Column(db.UnicodeText)

    auth = authcode.Auth(SECRET_KEY, db=db, UserMixin=UserMixin, RoleMixin=RoleMixin)
    authcode.setup_for_flask(auth, app)
    User = auth.User

    db.create_all()
    user = User(u'meh', u'text@example.com')
    db.session.add(user)
    db.session.commit()

    assert user.login == u'meh'
    assert user.email == u'text@example.com'
    assert hasattr(user, 'password')
    assert hasattr(user, 'last_sign_in')
    assert repr(user) == '<User meh>'


def test_setup_flask_custom():
    app = Flask(__name__)
    db = SQLAlchemy('sqlite:///', app)
    auth = authcode.Auth(SECRET_KEY, db=db)

    def send_email(user, subject, msg):
        pass

    def render(tmpl, **kwargs):
        pass

    class CustomSession(object):
        pass
    session = CustomSession()

    authcode.setup_for_flask(
        auth, app,
        render=render, send_email=send_email, session=session
    )
    assert auth.render == render
    assert auth.send_email == send_email
    assert auth.session == session


def test_setup_flask_no_views():
    app = Flask(__name__)
    db = SQLAlchemy('sqlite:///', app)
    auth = authcode.Auth(SECRET_KEY, db=db, views=[])

    authcode.setup_for_flask(auth, app)
    assert len(app.url_map._rules) == 1


def test_setup_flask_partial_views_1():
    app = Flask(__name__)
    db = SQLAlchemy('sqlite:///', app)
    auth = authcode.Auth(SECRET_KEY, db=db, views='sign_in sign_out'.split())

    authcode.setup_for_flask(auth, app)
    rules = app.url_map._rules
    names = [ru.endpoint for ru in rules]

    assert 'auth_sign_in' in names
    assert 'auth_sign_out' in names
    assert 'auth_reset_password' not in names
    assert 'auth_change_password' not in names


def test_setup_flask_partial_views_2():
    app = Flask(__name__)
    db = SQLAlchemy('sqlite:///', app)
    auth = authcode.Auth(SECRET_KEY, db=db, views='change_password'.split())

    authcode.setup_for_flask(auth, app)
    rules = app.url_map._rules
    names = [ru.endpoint for ru in rules]

    assert 'auth_sign_in' not in names
    assert 'auth_sign_out' not in names
    assert 'auth_reset_password' not in names
    assert 'auth_change_password' in names


def test_setup_flask_views_urls():
    app = Flask(__name__)
    db = SQLAlchemy('sqlite:///', app)
    config = {
        'url_sign_in': '/ingresar/',
        'url_sign_out': '/salir/',
        'url_reset_password': '/restablecer-contrasena/',
        'url_change_password': '/cambiar-contrasena/',
    }
    auth = authcode.Auth(SECRET_KEY, db=db, **config)

    authcode.setup_for_flask(auth, app)
    rules = app.url_map._rules
    endpoints = dict([(ru.endpoint, ru.rule) for ru in rules])

    assert endpoints['auth_sign_in'] == config['url_sign_in']
    assert endpoints['auth_sign_out'] == config['url_sign_out']
    assert endpoints['auth_change_password'] == config['url_change_password']
    assert endpoints['auth_reset_password'] == config['url_reset_password'] + '<token>/'


def test_setup_flask_views_callable_urls():
    app = Flask(__name__)
    db = SQLAlchemy('sqlite:///', app)
    config = {
        'url_sign_in': lambda: '/my-login',
        'url_reset_password': lambda: '/reset-secret',
    }
    auth = authcode.Auth(SECRET_KEY, db=db, **config)

    authcode.setup_for_flask(auth, app)
    rules = app.url_map._rules
    endpoints = dict([(ru.endpoint, ru.rule) for ru in rules])

    assert endpoints['auth_sign_in'] == '/my-login'
    assert endpoints['auth_reset_password'] == '/reset-secret/<token>/'
