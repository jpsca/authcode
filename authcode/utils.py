# coding=utf-8
from __future__ import print_function

import hashlib
import hmac
from time import time

from ._compat import to_bytes


def test_hasher(hasher):
    hasher.encrypt('test', rounds=hasher.min_rounds)


def to36(number):
    alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    base36 = ''
    while number:
        number, i = divmod(number, 36)
        base36 = alphabet[i] + base36

    return base36 or alphabet[0]


def from36(number):
    return int(number, 36)


def get_hash_extract(hash):
    half = hash.rsplit('$', 1)[0]
    return half[-10:]


def get_uhmac(user, secret):
    """Make an unique identifier for the user (stored in the session),
    so it can stay logged between requests.

    By hashing a snippet of the current password hash salt, it makes possible
    to automatically logout from all other devices just by changing
    (or refreshing) the password.
    """
    secret = to_bytes(secret)
    key = '|'.join([
        hashlib.sha1(secret).hexdigest(),
        str(user.id),
        get_hash_extract(user.password),
    ])
    key = key.encode('utf8', 'ignore')
    mac = hmac.new(key, msg=None, digestmod=hashlib.sha512)
    mac = mac.hexdigest()[:50]
    uhmac = '{0}${1}'.format(user.id, mac)
    return uhmac


def get_token(user, secret, timestamp=None):
    """Make a timestamped one-time-use token that can be used to
    identifying the user.

    By hashing the `last_sign_in` attribute and a snippet of the current
    password hash salt, it produces a token that will be invalidated as soon
    as the user log in again or the is changed.

    A hash of the user ID is used, so the HMAC part of the token is always
    unique for each user.

    It also hash a secret key, so without access to the source code,
    fake tokens cannot be generated even if the database is compromised.
    """
    timestamp = int(timestamp or time())
    secret = to_bytes(secret)
    key = '|'.join([
        hashlib.sha1(secret).hexdigest(),
        str(user.id),
        get_hash_extract(user.password),
        str(getattr(user, 'last_sign_in', 0)),
        str(timestamp),
    ])
    key = key.encode('utf8', 'ignore')
    mac = hmac.new(key, msg=None, digestmod=hashlib.sha512)
    mac = mac.hexdigest()[:50]
    token = '{0}${1}${2}'.format(user.id, to36(timestamp), mac)
    return token


def split_uhmac(uhmac):
    uid, mac = uhmac.split('$', 1)
    return uid


def split_token(token):
    uid, t36, mac = token.split('$', 2)
    return from36(t36), uid


def default_render(template, **context):
    from jinja2 import Environment, PackageLoader
    loader = PackageLoader('authcode', 'templates')
    env = Environment(loader=loader)
    tmpl = env.get_template(template)
    return tmpl.render(context)


def default_send_email(user, subject, msg):  # pragma: no cover
    print(user, subject, msg)


class LazyUser(object):
    """Acts as a proxy for the current user.  Forwards all operations to
    the proxied user.  The only operations not supported for forwarding
    are right handed operands and any kind of assignment.
    """
    __slots__ = ('__auth', '__storage', '__dict__')

    def __init__(self, auth, storage):
        object.__setattr__(self, '_LazyUser__auth', auth)
        object.__setattr__(self, '_LazyUser__storage', storage)
        setattr(storage, 'user', self)

    def __get_user(self):
        """Return the current object.  This is useful if you want the real
        object behind the proxy at a time for performance reasons or because
        you want to pass the object into a different context.
        """
        storage = object.__getattribute__(self, '_LazyUser__storage')
        user = getattr(self.__auth, 'get_user')()
        setattr(storage, 'user', user)
        return user

    @property
    def __dict__(self):
        return self.__get_user().__dict__

    def __doc__(self):
        return self.__get_user().__doc__

    def __repr__(self):
        return repr(self.__get_user())

    def __bool__(self):
        return bool(self.__get_user())

    __nonzero__ = __bool__

    def __str__(self):
        return str(self.__get_user())

    def __unicode__(self):
        return unicode(self.__get_user())

    def __dir__(self):
        return dir(self.__get_user())

    def __getattr__(self, name):
        return getattr(self.__get_user(), name)

    def __setattr__(self, name, value):
        setattr(self.__get_user(), name, value)

    def __delattr__(self, name, value):  # pragma: no cover
        delattr(self.__get_user(), name)

    def __setitem__(self, key, value):  # pragma: no cover
        self.__get_user()[key] = value

    def __delitem__(self, key):  # pragma: no cover
        del self.__get_user()[key]

    def __setslice__(self, i, j, seq):  # pragma: no cover
        self.__get_user()[i:j] = seq

    def __delslice__(self, i, j):  # pragma: no cover
        del self.__get_user()[i:j]

    def __lt__(self, other):  # pragma: no cover
        return self.__get_user() < other

    def __le__(self, other):  # pragma: no cover
        return self.__get_user() <= other

    def __eq__(self, other):  # pragma: no cover
        return self.__get_user() == other

    def __ne__(self, other):  # pragma: no cover
        return self.__get_user() != other

    def __gt__(self, other):  # pragma: no cover
        return self.__get_user() > other

    def __ge__(self, other):  # pragma: no cover
        return self.__get_user() >= other

    def __cmp__(self, other):  # pragma: no cover
        return cmp(self.__get_user(), other)

    def __hash__(self):  # pragma: no cover
        return hash(self.__get_user())

    def __call__(self, *args, **kwargs):  # pragma: no cover
        return self.__get_user()(*args, **kwargs)

    def __getitem__(self, i):  # pragma: no cover
        return self.__get_user()[i]

    def __iter__(self):  # pragma: no cover
        return iter(self.__get_user())

    def __contains__(self, i):  # pragma: no cover
        return i in self.__get_user()

    def __getslice__(self, i, j):  # pragma: no cover
        return self.__get_user()[i:j]

    def __add__(self, other):  # pragma: no cover
        return self.__get_user() + other

    def __sub__(self, other):  # pragma: no cover
        return self.__get_user() - other

    def __mul__(self, other):  # pragma: no cover
        return self.__get_user() * other

    def __floordiv__(self, other):  # pragma: no cover
        return self.__get_user() // other

    def __mod__(self, other):  # pragma: no cover
        return self.__get_user() % other

    def __divmod__(self, other):  # pragma: no cover
        return self.__get_user().__divmod__(other)

    def __pow__(self, other):  # pragma: no cover
        return self.__get_user() ** other

    def __lshift__(self, other):  # pragma: no cover
        return self.__get_user() << other

    def __rshift__(self, other):  # pragma: no cover
        return self.__get_user() >> other

    def __and__(self, other):  # pragma: no cover
        return self.__get_user() & other

    def __xor__(self, other):  # pragma: no cover
        return self.__get_user() ^ other

    def __or__(self, other):  # pragma: no cover
        return self.__get_user() | other

    def __div__(self, other):  # pragma: no cover
        return self.__get_user().__div__(other)

    def __truediv__(self, other):  # pragma: no cover
        return self.__get_user().__truediv__(other)

    def __neg__(self):  # pragma: no cover
        return -(self.__get_user())

    def __pos__(self):  # pragma: no cover
        return +(self.__get_user())

    def __abs__(self):  # pragma: no cover
        return abs(self.__get_user())

    def __len__(self):  # pragma: no cover
        return len(self.__get_user())

    def __invert__(self):  # pragma: no cover
        return ~(self.__get_user())

    def __complex__(self):  # pragma: no cover
        return complex(self.__get_user())

    def __int__(self):  # pragma: no cover
        return int(self.__get_user())

    def __long__(self):  # pragma: no cover
        return long(self.__get_user())

    def __float__(self):  # pragma: no cover
        return float(self.__get_user())

    def __oct__(self):  # pragma: no cover
        return oct(self.__get_user())

    def __hex__(self):  # pragma: no cover
        return hex(self.__get_user())

    def __index__(self):  # pragma: no cover
        return self.__get_user().__index__()

    def __coerce__(self, other):  # pragma: no cover
        return self.__get_user().__coerce__(self, other)

    def __enter__(self):  # pragma: no cover
        return self.__get_user().__enter__()

    def __exit__(self, *args, **kwargs):  # pragma: no cover
        return self.__get_user().__exit__(*args, **kwargs)
