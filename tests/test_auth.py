# coding=utf-8
from __future__ import print_function

import pytest
import authcode
from authcode._compat import to_unicode
from authcode.constants import DEFAULT_HASHER
from sqlalchemy_wrapper import SQLAlchemy
from passlib import hash as ph
from passlib.exc import MissingBackendError

from helpers import SECRET_KEY


try:
    ph.bcrypt.encrypt('test', rounds=ph.bcrypt.min_rounds)
    bcrypt_available = True
except MissingBackendError:
    bcrypt_available = False


def test_user_db():
    db = SQLAlchemy()

    auth = authcode.Auth(SECRET_KEY, db=db)
    User = auth.User

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.flush()

    assert user.login == u'meh'
    assert hasattr(user, 'password')
    assert hasattr(user, 'last_sign_in')
    assert repr(user) == '<User meh>'


def test_extended_user_db():
    db = SQLAlchemy()

    class UserMixin(object):
        email = db.Column(db.Unicode(300))

        def __repr__(self):
            return 'overwrited'

    class RoleMixin(object):
        description = db.Column(db.UnicodeText)

    auth = authcode.Auth(SECRET_KEY, db=db,
        UserMixin=UserMixin, RoleMixin=RoleMixin)
    User = auth.User
    Role = auth.Role

    db.create_all()
    user = User(login=u'meh', password='foobar', email=u'text@example.com')
    db.session.add(user)
    db.flush()

    assert User.__tablename__ == 'users'
    assert user.login == u'meh'
    assert user.email == u'text@example.com'
    assert hasattr(user, 'password')
    assert hasattr(user, 'last_sign_in')
    assert repr(user) == 'overwrited'

    assert hasattr(Role, 'description')


def test_flask_sqlalchemy():
    from flask import Flask
    from flask.ext.sqlalchemy import SQLAlchemy

    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'
    db = SQLAlchemy(app)


    class UserMixin(object):
        email = db.Column(db.Unicode(300))

        def __init__(self, login, email):
            self.login = login
            self.email = email
            self.password = 'foobar'


    class RoleMixin(object):
        description = db.Column(db.UnicodeText)


    auth = authcode.Auth(SECRET_KEY, db=db,
        UserMixin=UserMixin, RoleMixin=RoleMixin)
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


def test_automatic_password_hashing():
    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db, hash='pbkdf2_sha512', rounds=10)

    User = auth.User

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.session.commit()

    assert user.password
    assert user.password != 'foobar'
    assert user.has_password('foobar')


def test_hash_password():
    p = 'password'
    auth = authcode.Auth(SECRET_KEY, hash='pbkdf2_sha512', rounds=345)
    hashed = auth.hash_password(p)
    assert hashed.startswith('$pbkdf2-sha512$345$')
    assert auth.password_is_valid(p, hashed)
    assert not auth.password_is_valid(p, 'lalala')


def test_use_pepper():
    p = 'password'
    auth = authcode.Auth(SECRET_KEY, pepper='123', hash='sha512_crypt')
    hashed = auth.hash_password(p)
    assert auth.password_is_valid(p, hashed)
    auth = authcode.Auth(SECRET_KEY, pepper='abc', hash='sha512_crypt')
    assert not auth.password_is_valid(p, hashed)


def test_legacy_reader():
    p = 'password'
    auth = authcode.Auth(SECRET_KEY, hash='pbkdf2_sha512', rounds=345)
    hashed1 = ph.hex_sha1.encrypt(p)
    hashed2 = ph.django_salted_sha1.encrypt(p)

    assert auth.password_is_valid(p, hashed1)
    assert auth.password_is_valid(p, hashed2)


def test_set_raw_password():
    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db, roles=True)
    User = auth.User
    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.session.commit()

    user.set_raw_password('meh')
    db.session.commit()
    assert user.password == 'meh'


def test_sql_injection():
    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db, roles=True)
    User = auth.User
    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.session.commit()

    tests = [
        "1'; DELETE FROM users",
        '1"; DELETE FROM users',
        "1' --",
    ]
    for passw in tests:
        user.set_raw_password(passw)
        db.session.commit()
        assert user.password == passw


def test_authenticate_with_password():
    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db)

    User = auth.User

    db.create_all()
    credentials = {'login':u'meh', 'password':'foobar'}
    user = User(**credentials)
    db.session.add(user)
    db.session.commit()
    auth_user = auth.authenticate(credentials)
    assert user.login == auth_user.login

    auth_user = auth.authenticate({})
    assert not auth_user

    auth_user = auth.authenticate({'login':u'meh'})
    assert not auth_user

    auth_user = auth.authenticate({'login':u'wtf', 'password':'foobar'})
    assert not auth_user

    auth_user = auth.authenticate({'login':u'meh', 'password':'lalala'})
    assert not auth_user


def test_update_on_authenticate():
    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db, hash='pbkdf2_sha512',
                         update_hash=True)
    User = auth.User
    db.create_all()

    credentials = {'login':u'meh', 'password':'foobar'}
    user = User(**credentials)
    db.session.add(user)
    db.session.commit()

    assert user.password.startswith('$pbkdf2-sha512$')

    deprecated_hash = ph.hex_sha1.encrypt(credentials['password'])
    user.set_raw_password(deprecated_hash)
    db.session.commit()
    assert user.password == deprecated_hash

    auth_user = auth.authenticate(credentials)
    new_hash = auth_user.password
    assert new_hash != deprecated_hash
    assert new_hash.startswith('$pbkdf2-sha512$')


def test_disable_update_on_authenticate():
    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db, hash='pbkdf2_sha512',
                         update_hash=False)
    User = auth.User
    db.create_all()

    credentials = {'login':u'meh', 'password':'foobar'}
    user = User(**credentials)
    db.session.add(user)
    db.session.commit()

    deprecated_hash = ph.hex_sha1.encrypt(credentials['password'])
    assert user.password != deprecated_hash
    user.set_raw_password(deprecated_hash)
    db.session.commit()
    assert user.password == deprecated_hash

    auth_user = auth.authenticate(credentials)
    assert auth_user.password == deprecated_hash


def test_get_token():
    from time import time, sleep
    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db)

    User = auth.User

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.session.commit()

    token1 = user.get_token()
    sleep(1)
    token2 = user.get_token()
    assert token1 != token2

    timestamp = time()
    token1 = user.get_token(timestamp)
    token2 = user.get_token(timestamp)
    assert token1 == token2


def test_authenticate_with_token():
    from time import time
    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db, token_life=3*60)

    User = auth.User

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.session.commit()

    token = user.get_token()
    auth_user = auth.authenticate({'token':token})
    assert auth_user

    token = '555' + user.get_token()
    auth_user = auth.authenticate({'token':token})
    assert not auth_user

    auth_user = auth.authenticate({'token': ''})
    assert not auth_user

    timestamp = int(time()) - auth.token_life + 1
    token = user.get_token(timestamp)
    auth_user = auth.authenticate({'token':token})
    assert auth_user

    timestamp = int(time()) - auth.token_life - 1
    token = user.get_token(timestamp)
    auth_user = auth.authenticate({'token':token})
    assert not auth_user


def test_get_uhmac():
    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db)

    User = auth.User

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.session.commit()

    assert user.get_uhmac()
    assert user.get_uhmac() == user.get_uhmac()


def test_login_logout():
    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db)

    User = auth.User

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.session.commit()

    log = []

    session = {}
    auth.login(user, session=session)
    print(session)
    assert session[auth.session_key] == user.get_uhmac()
    auth.logout(session=session)
    assert auth.session_key not in session


def test_get_user():
    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db)

    User = auth.User

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.session.commit()

    session = {}
    assert auth.get_user(session=session) is None

    session = {auth.session_key: user.get_uhmac()}
    assert auth.get_user(session=session)

    session = {auth.session_key: 'foobar'}
    assert auth.get_user(session=session) is None
    assert session.get(auth.session_key) is None

    session = {auth.session_key: 'foobar' + user.get_uhmac()}
    assert auth.get_user(session=session) is None
    assert session.get(auth.session_key) is None


def test_user_role_model():
    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db, roles=True)
    User = auth.User
    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.session.commit()

    assert hasattr(auth, 'Role')
    assert hasattr(User, 'roles')

    user.add_role('admin')
    db.session.commit()
    assert user.has_role('admin')
    assert repr(user.roles[0]) == '<Role admin>'

    user.remove_role('admin')
    db.session.commit()
    assert not user.has_role('admin')

    user.remove_role('admin')
    db.session.commit()
    user.remove_role('foobar')
    db.session.commit()


def test_get_csrf_token():
    auth = authcode.Auth(SECRET_KEY)
    session = {}
    token = auth.get_csrf_token(session=session)
    assert token == auth.get_csrf_token(session=session)
    session = {}
    assert token != auth.get_csrf_token(session=session)
