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


def test_get_hash_extract():
    hash = u'$pbkdf2-sha512$19000$Y4wRAqA05rzX0123456789$fP0ECUz1LUtw...'
    assert utils.get_hash_extract('') == u''
    assert utils.get_hash_extract(None) == u''
    assert utils.get_hash_extract(hash) == u'0123456789'


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
    assert lazy == user
    assert storage.user == user

    storage.user = None
    assert not lazy != user
    assert storage.user == user

    storage.user = None
    assert lazy and user == user
    assert storage.user == user

    storage.user = None
    assert lazy or user == user
    assert storage.user == user

    storage.user = None
    assert hash(lazy) == hash(user)
    assert storage.user == user

    storage.user = None
    delattr(lazy, 'last_sign_in')
    assert storage.user == user
    assert getattr(user, 'last_sign_in', None) is None


def test_lazy_user_unusual_methods():
    class UserMixin(object):

        items = []

        def __lt__(self, other):
            return True

        def __le__(self, other):
            return True

        def __gt__(self, other):
            return True

        def __ge__(self, other):
            return True

        def __call__(self, *args, **kwargs):
            return 'called'

        def __setitem__(self, key, value):
            self.items[key] = value

        def __delitem__(self, key):
            del self.items[key]

        def __getitem__(self, i):
            return self.items[i]

        def __contains__(self, i):
            return i in self.items

        def __iter__(self):
            return iter(self.items)

        def __add__(self, other):
            return 42

        def __sub__(self, other):
            return 42

        def __mul__(self, other):
            return 42

        def __floordiv__(self, other):
            return 42

        def __mod__(self, other):
            return 42

        def __divmod__(self, other):
            return (42, 0)

        def __pow__(self, other):
            return 42

        def __lshift__(self, other):
            return 42

        def __rshift__(self, other):
            return 42

        def __and__(self, other):
            return 42

        def __or__(self, other):
            return 42

        def __xor__(self, other):
            return 42

        def __div__(self, other):
            return 42

        def __truediv__(self, other):
            return 42

        def __neg__(self):
            return -42

        def __pos__(self):
            return 42

        def __abs__(self):
            return 42

        def __len__(self):
            return 42

        def __complex__(self):
            return 42j

        def __int__(self):
            return 42

        def __float__(self):
            return 42.0

        def __invert__(self):
            return 42

        def __enter__(self):
            return self.items.insert(0, 'enter')

        def __exit__(self, *args, **kwargs):
            return self.items.append('exit')

    db = SQLAlchemy()
    auth = authcode.Auth(SECRET_KEY, db=db, UserMixin=UserMixin)
    User = auth.User
    db.create_all()
    user = User(login=u'meh', password='foobar')
    db.session.add(user)
    other = User(login=u'foobar', password='foobar')
    db.session.add(other)
    db.commit()

    storage = Meh()
    lazy = utils.LazyUser(auth, storage)

    user.items = 'a b c d e f g'.split(' ')
    auth.login(user)

    assert lazy >= user

    assert lazy <= user

    assert lazy > user

    assert lazy < user

    assert lazy() == 'called'

    lazy[0] = 'a'  # __setitem__
    assert user.items[0] == 'a'

    del lazy[1]  # __delitem__
    assert lazy[1] == 'c'  # __getitem__

    assert 'f' in lazy  # __contains__

    assert list(iter(lazy)) == list(iter(user))  # __iter__

    assert lazy + 1 == 42  # __add__

    assert lazy - 1 == 42  # __sub__

    assert lazy * 3 == 42  # __mul__

    assert lazy / 3 == 42  # __div__

    assert lazy.__floordiv__(3) == 42  # __floordiv__

    assert lazy.__truediv__(3) == 42  # __truediv__

    assert lazy % 33 == 42  # __mod__

    assert divmod(lazy, 5) == (42, 0)  # __divmod__

    assert lazy ** 3 == 42  # __pow__

    assert lazy << 1 == 42  # __lshift__

    assert lazy >> 1 == 42  # __rshift__

    assert lazy & 6 == 42  # __and__

    assert lazy | 6 == 42  # __or__

    assert lazy ^ 6 == 42  # __xor__

    assert -lazy == -42  # __neg__

    assert +lazy == 42  # __pos__

    assert abs(lazy) == 42  # __abs__

    assert len(lazy) == 42  # __len__

    assert int(lazy) == 42  # __int__

    assert float(lazy) == 42.0  # __float__

    assert ~lazy == 42  # __invert__

    assert lazy.__complex__() == 42j  # __complex__

    with lazy:  # __enter__ and __exit__
        pass
    assert user.items[0] == 'enter'
    assert user.items[-1] == 'exit'


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
