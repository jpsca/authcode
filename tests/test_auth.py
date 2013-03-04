# -*- coding: utf-8 -*-
import pytest
import authcode
from orm import SQLAlchemy
from passlib import hash as ph
from passlib.exc import MissingBackendError

from helpers import *


try:
    ph.bcrypt.encrypt('test', rounds=ph.bcrypt.min_rounds)
    bcrypt_available = True
except MissingBackendError:
    bcrypt_available = False


def test_user_db():
    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db)

    class User(auth.User):
        pass

    user = User(login=u'meh', password='foobar')
    
    assert hasattr(User, 'login')
    assert hasattr(User, 'password')
    assert hasattr(User, 'created_at')
    assert hasattr(User, 'modified_at')
    assert hasattr(User, 'last_sign_in')
    assert repr(user) == '<User meh>'


def test_automatic_password_hashing():
    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db, hash='pbkdf2_sha512', rounds=10)

    class User(auth.User):
        pass

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.add(user)
    db.commit()

    assert user.modified_at
    assert user.password
    assert user.password != 'foobar'
    assert user.has_password('foobar')


def test_select_hashing_alg():
    auth = authcode.Auth(SECRET_KEY, rounds=0)
    assert auth.rounds == 1

    auth = authcode.Auth(SECRET_KEY)
    if bcrypt_available:
        assert auth.hash == 'bcrypt'
    else:
        assert auth.hash == 'pbkdf2-sha512'
        auth = authcode.Auth(SECRET_KEY, hash='bcrypt')
        assert auth.hash == 'pbkdf2-sha512'
    assert auth.rounds

    auth = authcode.Auth(SECRET_KEY, hash='sha512_crypt', rounds=1500)
    assert auth.hash == 'sha512-crypt'
    assert auth.rounds == 1500

    with pytest.raises(authcode.exceptions.WrongHashAlgorithm):
        auth = authcode.Auth(SECRET_KEY, hash='lalala')


def test_exceptions():
    assert '`bcrypt`' in str(authcode.exceptions.WrongHashAlgorithm())
    assert '`pbkdf2_sha512`' in str(authcode.exceptions.WrongHashAlgorithm())
    assert '`sha512_crypt`' in str(authcode.exceptions.WrongHashAlgorithm())


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
    from passlib.hash import hex_sha1, django_salted_sha1
    p = 'password'
    auth = authcode.Auth(SECRET_KEY, hash='pbkdf2_sha512', rounds=345)
    hashed1 = hex_sha1.encrypt(p)
    hashed2 = django_salted_sha1.encrypt(p)
    
    assert auth.password_is_valid(p, hashed1)
    assert auth.password_is_valid(p, hashed2)


def test_authenticate_with_password():
    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db)

    class User(auth.User):
        pass

    db.create_all()
    credentials = {'login':u'meh', 'password':'foobar'}
    user = User(**credentials)
    db.add(user)
    db.commit()
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


def test_monkeypatching_authentication():
    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db)

    class User(auth.User):
        pass

    db.create_all()
    user = User(login=u'meh')
    db.add(user)
    db.commit()

    def verify_and_update(secret, hashed):
        if secret == 'foobar':
            return True, auth.hash_password(secret)
        return auth._verify_and_update(secret, hashed)
    
    auth._verify_and_update = auth.verify_and_update
    auth.verify_and_update = verify_and_update
    assert auth.authenticate(dict(login=u'meh', password='foobar'))


def test_update_on_authenticate():
    from passlib.hash import hex_sha1
    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db, hash='pbkdf2_sha512', rounds=10)

    class User(auth.User):
        pass

    db.create_all()
    credentials = {'login':u'meh', 'password':'foobar'}
    user = User(**credentials)
    user._password = hex_sha1.encrypt(credentials['password'])
    db.add(user)
    db.commit()
    
    assert not user.password.startswith('$pbkdf2-sha512$')
    auth_user = auth.authenticate(credentials)
    assert auth_user.password.startswith('$pbkdf2-sha512$')


def test_disable_update_on_authenticate():
    from passlib.hash import hex_sha1
    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db, hash='pbkdf2_sha512', rounds=10, update_hash=False)

    class User(auth.User):
        pass

    db.create_all()
    credentials = {'login':u'meh', 'password':'foobar'}
    user = User(**credentials)
    hashed = hex_sha1.encrypt(credentials['password'])
    user._password = hashed
    db.add(user)
    db.commit()
    
    auth_user = auth.authenticate(credentials)
    assert auth_user.password == hashed


def test_get_token():
    from time import time, sleep
    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db)

    class User(auth.User):
        pass

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.add(user)
    db.commit()
    
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

    class User(auth.User):
        pass

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.add(user)
    db.commit()

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

    class User(auth.User):
        pass

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.add(user)
    db.commit()

    assert user.get_uhmac()
    assert user.get_uhmac() == user.get_uhmac()


def test_login_logout():
    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db)

    class User(auth.User):
        pass

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.add(user)
    db.commit()

    log = []

    session = {}
    auth.login(user, session=session)
    print session
    assert session[auth.session_key] == user.get_uhmac()
    auth.logout(session=session)
    assert auth.session_key not in session


def test_get_user():
    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db)

    class User(auth.User):
        pass

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.add(user)
    db.commit()

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

    class User(auth.User):
        pass

    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.add(user)
    db.commit()

    assert hasattr(auth, 'Role')
    assert hasattr(User, 'roles')

    user.add_role('admin')
    db.commit()
    assert user.has_role('admin')
    assert repr(user.roles[0]) == '<Role admin>'

    user.remove_role('admin')
    db.commit()
    assert not user.has_role('admin')

    user.remove_role('admin')    
    db.commit()

    with pytest.raises(ValueError):
        user.remove_role('foobar')


def test_get_csrf_token():
    auth = authcode.Auth(SECRET_KEY)
    session = {}
    token = auth.get_csrf_token(session=session)
    assert token == auth.get_csrf_token(session=session)
    session = {}
    assert token != auth.get_csrf_token(session=session)

