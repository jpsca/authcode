# coding=utf-8
from __future__ import print_function

import hashlib
import hmac
from time import time

from ._compat import to_bytes, implements_to_string, implements_bool


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


def get_uhmac(user, secret):
    secret = to_bytes(secret)
    key = '|'.join([
        hashlib.sha1(secret).hexdigest(),
        str(user.id),
        (getattr(user, 'password', '') or '')[10:20],
    ])
    key = key.encode('utf8', 'ignore')
    mac = hmac.new(key, msg=None, digestmod=hashlib.sha512)
    mac = mac.hexdigest()[:50]
    # user.id instead of user.login because SQLAlchemy only caches
    # by primary key, so even if you don't cache the user object, a trip to
    # the database is spared.
    uhmac = '{0}${1}'.format(user.id, mac)
    return uhmac


def get_token(user, secret, timestamp=None):
    """Make a timestamped one-time-use token that can be used to
    identifying the user.

    By hashing the `last_sign_in` attribute and the password salt, it produce
    a token that will be invalidated as soon as the user log in again or the
    is changed.

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
        (getattr(user, 'password', '') or '')[10:20],
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


def default_send_email(user, subject, msg):
    print(user, subject, msg)


@implements_to_string
@implements_bool
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

    def _get_user(self):
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
        try:
            return self._get_user().__dict__
        except RuntimeError:
            raise AttributeError('__dict__')

    def __repr__(self):
        try:
            obj = self._get_user()
        except RuntimeError:
            return '<%s unbound>' % self.__class__.__name__
        return repr(obj)

    def __nonzero__(self):
        try:
            return bool(self._get_user())
        except RuntimeError:
            return False

    def __unicode__(self):
        try:
            return unicode(self._get_user())
        except RuntimeError:
            return repr(self)

    def __dir__(self):
        try:
            return dir(self._get_user())
        except RuntimeError:
            return []

    def __getattr__(self, name):
        if name == '__members__':
            return dir(self._get_user())
        return getattr(self._get_user(), name)

    def __setitem__(self, key, value):
        self._get_user()[key] = value

    def __delitem__(self, key):
        del self._get_user()[key]

    def __setslice__(self, i, j, seq):
        self._get_user()[i:j] = seq

    def __delslice__(self, i, j):
        del self._get_user()[i:j]

    __str__ = lambda x: str(x._get_user())
    __bool__ = lambda x: x._get_user() is not None

    __setattr__ = lambda x, n, v: setattr(x._get_user(), n, v)
    __delattr__ = lambda x, n: delattr(x._get_user(), n)
    __lt__ = lambda x, o: x._get_user() < o
    __le__ = lambda x, o: x._get_user() <= o
    __eq__ = lambda x, o: x._get_user() == o
    __ne__ = lambda x, o: x._get_user() != o
    __gt__ = lambda x, o: x._get_user() > o
    __ge__ = lambda x, o: x._get_user() >= o
    __cmp__ = lambda x, o: cmp(x._get_user(), o)
    __hash__ = lambda x: hash(x._get_user())
    __call__ = lambda x, *a, **kw: x._get_user()(*a, **kw)
    __getitem__ = lambda x, i: x._get_user()[i]
    __iter__ = lambda x: iter(x._get_user())
    __contains__ = lambda x, i: i in x._get_user()
    __getslice__ = lambda x, i, j: x._get_user()[i:j]
    __add__ = lambda x, o: x._get_user() + o
    __sub__ = lambda x, o: x._get_user() - o
    __mul__ = lambda x, o: x._get_user() * o
    __floordiv__ = lambda x, o: x._get_user() // o
    __mod__ = lambda x, o: x._get_user() % o
    __divmod__ = lambda x, o: x._get_user().__divmod__(o)
    __pow__ = lambda x, o: x._get_user() ** o
    __lshift__ = lambda x, o: x._get_user() << o
    __rshift__ = lambda x, o: x._get_user() >> o
    __and__ = lambda x, o: x._get_user() & o
    __xor__ = lambda x, o: x._get_user() ^ o
    __or__ = lambda x, o: x._get_user() | o
    __div__ = lambda x, o: x._get_user().__div__(o)
    __truediv__ = lambda x, o: x._get_user().__truediv__(o)
    __neg__ = lambda x: -(x._get_user())
    __pos__ = lambda x: +(x._get_user())
    __abs__ = lambda x: abs(x._get_user())
    __len__ = lambda x: len(x._get_user())
    __invert__ = lambda x: ~(x._get_user())
    __complex__ = lambda x: complex(x._get_user())
    __int__ = lambda x: int(x._get_user())
    __long__ = lambda x: long(x._get_user())
    __float__ = lambda x: float(x._get_user())
    __oct__ = lambda x: oct(x._get_user())
    __hex__ = lambda x: hex(x._get_user())
    __index__ = lambda x: x._get_user().__index__()
    __coerce__ = lambda x, o: x.__coerce__(x, o)
    __enter__ = lambda x: x.__enter__()
    __exit__ = lambda x, *a, **kw: x.__exit__(*a, **kw)
