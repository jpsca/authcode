# coding=utf-8
from __future__ import print_function

import authcode
import pytest
from sqlalchemy_wrapper import SQLAlchemy
from passlib import hash as ph
from passlib.exc import MissingBackendError

from helpers import SECRET_KEY


try:
    ph.bcrypt.encrypt('test', rounds=ph.bcrypt.min_rounds)
    bcrypt_available = True
except MissingBackendError:
    bcrypt_available = False


def test_prefix():
    db = SQLAlchemy('sqlite:///:memory:')
    auth1 = authcode.Auth(SECRET_KEY, db=db, roles=True, prefix='foobar')

    assert auth1.users_model_name == 'FoobarUser'
    assert auth1.roles_model_name == 'FoobarRole'
    assert auth1.views_prefix == 'foobar_'
    assert auth1.url_sign_in == '/foobar/sign-in/'
    assert auth1.url_sign_out == '/foobar/sign-out/'
    assert auth1.url_reset_password == '/foobar/reset-password/'
    assert auth1.url_change_password == '/foobar/change-password/'

    auth2 = authcode.Auth(SECRET_KEY, db=db, roles=True, prefix='meh')

    assert auth2.users_model_name == 'MehUser'
    assert auth2.roles_model_name == 'MehRole'
    assert auth2.views_prefix == 'meh_'
    assert auth2.url_sign_in == '/meh/sign-in/'
    assert auth2.url_sign_out == '/meh/sign-out/'
    assert auth2.url_reset_password == '/meh/reset-password/'
    assert auth2.url_change_password == '/meh/change-password/'


def test_automatic_case_insensitiveness():
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(SECRET_KEY, db=db)
    User = auth.User
    db.create_all()
    user = User(login=u'MeH', password='foobar')
    db.session.add(user)
    db.session.commit()

    assert user.login == u'meh'
    assert User.by_login(u'MEH') == User.by_login(u'MeH') == user


def test_disabled_case_insensitiveness():
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(SECRET_KEY, db=db, case_insensitive=False)
    User = auth.User
    db.create_all()
    user = User(login=u'MeH', password='foobar')
    db.session.add(user)
    db.session.commit()

    assert user.login == u'MeH'
    assert not User.by_login(u'meh')
    assert not User.by_login(u'MEH')
    assert User.by_login(u'MeH') == user


def test_automatic_password_hashing():
    db = SQLAlchemy('sqlite:///:memory:')
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
    assert not auth.password_is_valid(p, None)
    assert not auth.password_is_valid(None, 'lalala')
    assert not auth.password_is_valid(None, None)


def test_hash_password_too_short():
    p = '123'
    auth = authcode.Auth(SECRET_KEY, hash='pbkdf2_sha512')
    with pytest.raises(ValueError):
        auth.hash_password(p)


def test_hash_password_too_long():
    p = '1' * 5000
    auth = authcode.Auth(SECRET_KEY, hash='pbkdf2_sha512')
    with pytest.raises(ValueError):
        auth.hash_password(p)


def test_huge_password_is_never_valid():
    auth = authcode.Auth(SECRET_KEY)
    p = '1' * 2000
    p = auth.prepare_password(p)
    hashed = auth.hasher.encrypt(p)
    assert not auth.password_is_valid(p, hashed)


def test_use_pepper():
    p = 'password'
    auth = authcode.Auth(SECRET_KEY, pepper='123', hash='sha512_crypt')
    hashed = auth.hash_password(p)
    assert auth.password_is_valid(p, hashed)

    auth = authcode.Auth(SECRET_KEY, pepper='abc', hash='sha512_crypt')
    assert not auth.password_is_valid(p, hashed)


def test_unsupported_hash():
    with pytest.raises(authcode.WrongHashAlgorithm):
        authcode.Auth(SECRET_KEY, hash='foobar')


def test_legacy_reader():
    p = 'password'
    auth = authcode.Auth(SECRET_KEY, hash='pbkdf2_sha512', rounds=345)
    hashed1 = ph.hex_sha1.encrypt(p)
    hashed2 = ph.django_salted_sha1.encrypt(p)

    assert auth.password_is_valid(p, hashed1)
    assert auth.password_is_valid(p, hashed2)


def test_sql_injection():
    db = SQLAlchemy('sqlite:///:memory:')
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
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(SECRET_KEY, db=db)

    User = auth.User

    db.create_all()
    credentials = {'login': u'meh', 'password': 'foobar'}
    user = User(**credentials)
    db.session.add(user)
    db.session.commit()

    auth_user = auth.authenticate(credentials)
    assert user.login == auth_user.login

    auth_user = auth.authenticate({})
    assert not auth_user

    auth_user = auth.authenticate({'login': u'meh'})
    assert not auth_user

    auth_user = auth.authenticate({'login': u'wtf', 'password': 'foobar'})
    assert not auth_user

    auth_user = auth.authenticate({'login': u'meh', 'password': 'lalala'})
    assert not auth_user


def test_user_has_none_password():
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(SECRET_KEY, db=db)

    User = auth.User

    db.create_all()
    user = User(login=u'meh', password=None)
    db.session.add(user)
    db.session.commit()

    assert user.password is None

    auth_user = auth.authenticate({})
    assert not auth_user

    auth_user = auth.authenticate({'login': u'meh', 'password': None})
    assert not auth_user

    auth_user = auth.authenticate({'login': u'meh'})
    assert not auth_user

    auth_user = auth.authenticate({'login': u'wtf', 'password': ''})
    assert not auth_user

    auth_user = auth.authenticate({'login': u'meh', 'password': 'lalala'})
    assert not auth_user


def test_user_has_empty_password():
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(SECRET_KEY, db=db, password_minlen=0)

    User = auth.User

    db.create_all()
    user = User(login=u'meh', password=u'')
    db.session.add(user)
    db.session.commit()

    assert user.password != u''

    auth_user = auth.authenticate({'login': u'meh', 'password': u''})
    assert auth_user

    auth_user = auth.authenticate({})
    assert not auth_user

    auth_user = auth.authenticate({'login': u'meh', 'password': None})
    assert not auth_user

    auth_user = auth.authenticate({'login': u'meh'})
    assert not auth_user

    auth_user = auth.authenticate({'login': u'wtf', 'password': ''})
    assert not auth_user

    auth_user = auth.authenticate({'login': u'meh', 'password': 'lalala'})
    assert not auth_user


def test_update_on_authenticate():
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(SECRET_KEY, db=db, hash='pbkdf2_sha512',
                         update_hash=True)
    User = auth.User
    db.create_all()

    credentials = {'login': u'meh', 'password': 'foobar'}
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
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(SECRET_KEY, db=db, hash='pbkdf2_sha512',
                         update_hash=False)
    User = auth.User
    db.create_all()

    credentials = {'login': u'meh', 'password': 'foobar'}
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
    db = SQLAlchemy('sqlite:///:memory:')
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
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(SECRET_KEY, db=db, token_life=3 * 60)

    User = auth.User

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.session.commit()

    token = user.get_token()
    auth_user = auth.authenticate({'token': token})
    assert auth_user

    token = '555' + user.get_token()
    auth_user = auth.authenticate({'token': token})
    assert not auth_user

    auth_user = auth.authenticate({'token': ''})
    assert not auth_user

    timestamp = int(time()) - auth.token_life + 1
    token = user.get_token(timestamp)
    auth_user = auth.authenticate({'token': token})
    assert auth_user

    timestamp = int(time()) - auth.token_life - 1
    token = user.get_token(timestamp)
    auth_user = auth.authenticate({'token': token})
    assert not auth_user


def test_get_uhmac():
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(SECRET_KEY, db=db)

    User = auth.User

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.session.commit()

    assert user.get_uhmac()
    assert user.get_uhmac() == user.get_uhmac()


def test_login_logout():
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(SECRET_KEY, db=db)

    User = auth.User

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.session.commit()

    session = {}
    auth.login(user, session=session)
    print(session)
    assert session[auth.session_key] == user.get_uhmac()
    auth.logout(session=session)
    assert auth.session_key not in session


def test_login_repeated_logout():
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(SECRET_KEY, db=db)

    User = auth.User

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.session.commit()

    session = {}
    auth.login(user, session=session)
    assert session[auth.session_key] == user.get_uhmac()

    auth.logout(session=session)
    assert auth.session_key not in session

    auth.logout(session=session)
    assert auth.session_key not in session


def test_clear_session_on_logout():
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(SECRET_KEY, db=db)

    User = auth.User

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.session.commit()

    session = {}
    auth.login(user, session=session)
    session['foo'] = 'bar'

    print(session)
    assert auth.session_key in session
    assert 'foo' in session

    auth.logout(session=session)
    print(session)
    assert auth.session_key not in session
    assert 'foo' not in session


def test_dont_clear_session_on_logout():
    db = SQLAlchemy('sqlite:///:memory:')
    auth = authcode.Auth(SECRET_KEY, db=db, clear_session_on_logout=False)

    User = auth.User

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.session.commit()

    session = {}
    auth.login(user, session=session)
    session['foo'] = 'bar'

    print(session)
    assert auth.session_key in session
    assert 'foo' in session

    auth.logout(session=session)
    print(session)
    assert auth.session_key not in session
    assert session['foo'] == 'bar'


def test_get_user():
    db = SQLAlchemy('sqlite:///:memory:')
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


def test_get_csrf_token():
    auth = authcode.Auth(SECRET_KEY)

    session = {}
    token = auth.get_csrf_token(session=session)
    assert not token.startswith('"b')
    assert token == auth.get_csrf_token(session=session)
    session = {}
    assert token != auth.get_csrf_token(session=session)


def test_replace_hash_password_method():
    """Can the library work the same with custom ``has_password`` and
    ``password_is_valid`` methods?
    """

    class CustomAuth(authcode.Auth):
        def hash_password(self, secret):
            secret = self.prepare_password(secret)
            return secret[::-1]

        def password_is_valid(self, secret, hashed):
            secret = self.prepare_password(secret)
            if secret is None or hashed is None:
                return False
            return self.hash_password(secret) == hashed

    db = SQLAlchemy('sqlite:///:memory:')
    auth = CustomAuth(SECRET_KEY, db=db)
    User = auth.User
    db.create_all()

    credentials = {'login': u'meh', 'password': 'foobar'}
    user = User(**credentials)
    db.session.add(user)
    db.session.commit()

    assert user.password == 'foobar'[::-1]
    assert user.has_password('foobar')

    auth_user = auth.authenticate(credentials)
    assert user.login == auth_user.login

    auth_user = auth.authenticate({})
    assert not auth_user
