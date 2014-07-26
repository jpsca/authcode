# coding=utf-8
from __future__ import print_function

import os
from datetime import datetime

from authcode import utils
from authcode._compat import text_type
from sqlalchemy_wrapper import SQLAlchemy
import authcode
import pytest

from helpers import SECRET_KEY


class User(object):
    id = 3
    password = '0123456789abcdefghijklmnopqrstuvwxyz'
    last_sign_in = datetime(2013, 5, 5)


def test_get_uhmac():
    secret = 'abcdefghijklmnopqrstuvwxyz'

    uhmac = utils.get_uhmac(User(), secret)
    assert uhmac.startswith('3$')


def test_get_uhmac_nonascii_secret():
    secret = os.urandom(32)

    uhmac = utils.get_uhmac(User(), secret)
    assert uhmac


def test_get_token():
    secret = 'abcdefghijklmnopqrstuvwxyz'
    assert utils.get_token(User(), secret)
    timestamp = '1234'
    token = utils.get_token(User(), secret, timestamp)
    assert token.startswith('3$YA$')


def test_get_token_nonascii_secret():
    secret = os.urandom(32)
    timestamp = '1234'
    token = utils.get_token(User(), secret, timestamp)
    assert token


class Meh(object):
    pass


def test_lazy_user():
    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db)
    User = auth.User
    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    db.commit()

    storage = Meh()
    lazy = utils.LazyUser(auth, storage)
    assert not storage.user
    assert not lazy

    storage.user = None
    auth.login(user)
    assert lazy
    assert storage.user == user

    storage.user = None
    assert lazy.login == user.login
    assert storage.user == user

    storage.user = None
    lazy.login = u'yeah'
    assert user.login == u'yeah'
    assert storage.user == user

    storage.user = None
    assert repr(lazy) == repr(user)
    assert storage.user == user

    storage.user = None
    assert str(lazy) == str(user)
    assert storage.user == user

    storage.user = None
    assert text_type(lazy) == text_type(user)
    assert storage.user == user

    storage.user = None
    assert lazy.__doc__ == user.__doc__
    assert storage.user == user

    storage.user = None
    assert user.__dict__ == lazy.__dict__
    assert storage.user == user

    storage.user = None
    assert dir(lazy) == dir(user)
    assert storage.user == user

    storage.user = None
    delattr(lazy, 'last_sign_in')
    assert storage.user == user
    assert getattr(user, 'last_sign_in', None) is None


def test_to36():
    assert utils.to36(0) == '0'
    assert utils.to36(10) == 'A'
    assert utils.to36(125) == '3H'
    assert utils.to36(143) == '3Z'
    assert utils.to36(144) == '40'
    assert len(utils.to36(pow(3, 1979))) == 607
    with pytest.raises(AssertionError):
        utils.to36(-1)
    with pytest.raises(ValueError):
        utils.to36('a')


def test_from36():
    assert utils.from36('0') == 0
    assert utils.from36('A') == 10
    assert utils.from36('a') == 10
    assert utils.from36('3H') == 125
    assert utils.from36('3Z') == 143
    assert utils.from36('40') == 144
    with pytest.raises(ValueError):
        utils.from36('!')
