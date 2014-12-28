# coding=utf-8
from __future__ import print_function

from flask import Flask, render_template
from sqlalchemy_wrapper import SQLAlchemy
import authcode
import pytest

from helpers import SECRET_KEY


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


def test_setup_flask_custom_render():
    app = Flask(__name__)
    db = SQLAlchemy('sqlite:///', app)
    auth = authcode.Auth(SECRET_KEY, db=db)

    def send_email(user, subject, msg):
        pass

    def render(tmpl, **kwargs):
        pass

    authcode.setup_for_flask(auth, app, send_email=send_email, render=render)
    assert auth.send_email == send_email
    assert auth.render == render
    assert app.jinja_env.globals['csrf_token']
    assert app.jinja_env.globals['auth']


def test_setup_flask_render():
    app = Flask(__name__)
    db = SQLAlchemy('sqlite:///', app)
    auth = authcode.Auth(SECRET_KEY, db=db)

    authcode.setup_for_flask(auth, app)
    assert auth.send_email
    assert auth.render == render_template
    assert app.jinja_env.globals['csrf_token']
    assert app.jinja_env.globals['auth']


def test_setup_flask_false_render():
    app = Flask(__name__)
    db = SQLAlchemy('sqlite:///', app)
    auth = authcode.Auth(SECRET_KEY, db=db)

    authcode.setup_for_flask(auth, app, render=None)
    assert auth.send_email
    assert auth.render == render_template
    assert app.jinja_env.globals['csrf_token']
    assert app.jinja_env.globals['auth']


def test_setup_flask_no_views():
    app = Flask(__name__)
    db = SQLAlchemy('sqlite:///', app)
    auth = authcode.Auth(SECRET_KEY, db=db, views=[])

    authcode.setup_for_flask(auth, app)
    assert len(app.url_map._rules) == 1


def test_setup_flask_default_views():
    app = Flask(__name__)
    db = SQLAlchemy('sqlite:///', app)
    auth = authcode.Auth(SECRET_KEY, db=db)

    authcode.setup_for_flask(auth, app)
    rules = app.url_map._rules
    endpoints = dict([(ru.endpoint, ru.rule) for ru in rules])

    assert 'auth_sign_in' in endpoints
    assert 'auth_sign_out' in endpoints
    assert 'auth_reset_password' in endpoints
    assert 'auth_change_password' in endpoints


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


def test_setup_flask_disable_sign_in_view():
    app = Flask(__name__)
    db = SQLAlchemy('sqlite:///', app)
    views = ['sign_out', 'reset_password', 'change_password', ]
    auth = authcode.Auth(SECRET_KEY, db=db, views=views)

    authcode.setup_for_flask(auth, app)
    rules = app.url_map._rules
    endpoints = dict([(ru.endpoint, ru.rule) for ru in rules])

    assert 'auth_sign_in' not in endpoints
    assert 'auth_sign_out' in endpoints
    assert 'auth_reset_password' in endpoints
    assert 'auth_change_password' in endpoints


def test_setup_flask_disable_sign_out_view():
    app = Flask(__name__)
    db = SQLAlchemy('sqlite:///', app)
    views = ['sign_in', 'reset_password', 'change_password', ]
    auth = authcode.Auth(SECRET_KEY, db=db, views=views)

    authcode.setup_for_flask(auth, app)
    rules = app.url_map._rules
    endpoints = dict([(ru.endpoint, ru.rule) for ru in rules])

    assert 'auth_sign_in' in endpoints
    assert 'auth_sign_out' not in endpoints
    assert 'auth_reset_password' in endpoints
    assert 'auth_change_password' in endpoints


def test_setup_flask_disable_reset_password_view():
    app = Flask(__name__)
    db = SQLAlchemy('sqlite:///', app)
    views = ['sign_in', 'sign_out', 'change_password', ]
    auth = authcode.Auth(SECRET_KEY, db=db, views=views)

    authcode.setup_for_flask(auth, app)
    rules = app.url_map._rules
    endpoints = dict([(ru.endpoint, ru.rule) for ru in rules])

    assert 'auth_sign_in' in endpoints
    assert 'auth_sign_out' in endpoints
    assert 'auth_reset_password' not in endpoints
    assert 'auth_change_password' in endpoints


def test_setup_flask_disable_change_password_view():
    app = Flask(__name__)
    db = SQLAlchemy('sqlite:///', app)
    views = ['sign_in', 'sign_out', 'reset_password', ]
    auth = authcode.Auth(SECRET_KEY, db=db, views=views)

    authcode.setup_for_flask(auth, app)
    rules = app.url_map._rules
    endpoints = dict([(ru.endpoint, ru.rule) for ru in rules])

    assert 'auth_sign_in' in endpoints
    assert 'auth_sign_out' in endpoints
    assert 'auth_reset_password' in endpoints
    assert 'auth_change_password' not in endpoints


# -----------------------------------------------------------------------------

def test_setup_shake_custom_render():
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

    render = Render()

    authcode.setup_for_shake(auth, app, send_email=send_email, render=render)
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
    auth = authcode.Auth(SECRET_KEY, db=db)

    authcode.setup_for_shake(auth, app, views=False)
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
