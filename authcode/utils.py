# coding=utf-8
import hashlib
import hmac
from time import time

from ._compat import to_bytes, to_unicode


def eval_url(url):
    if callable(url):
        url = url()
    return url


def test_hasher(hasher):
    hasher.encrypt('test', rounds=hasher.min_rounds)


def to36(number):
    assert int(number) >= 0, 'Must be a positive integer'
    alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    base36 = ''
    while number:
        number, i = divmod(number, 36)
        base36 = alphabet[i] + base36

    return base36 or alphabet[0]


def from36(snumber):
    snumber = snumber.upper()
    return int(snumber, 36)


def get_hash_extract(hash):
    if not hash:
        return u''
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


class LazyUser(object):
    """Acts as a proxy for the current user.  Forwards all operations to
    the proxied user.  The only operations not supported for forwarding
    are right handed operands and any kind of assignment.
    """
    __slots__ = ('__auth', '__storage', '__dict__')

    def __init__(self, auth, storage, user_name='user'):
        object.__setattr__(self, '_LazyUser__auth', auth)
        object.__setattr__(self, '_LazyUser__storage', storage)
        object.__setattr__(self, '_LazyUser__user_name', user_name)
        setattr(storage, user_name, self)

    def __get_user(self):
        """Return the real user object.
        """
        storage = object.__getattribute__(self, '_LazyUser__storage')
        user = getattr(self.__auth, 'get_user')()
        setattr(storage, self.__user_name, user)
        return user

    @property
    def __dict__(self):
        return self.__get_user().__dict__

    @property
    def __doc__(self):
        return self.__get_user().__doc__

    def __repr__(self):
        return repr(self.__get_user())

    def __bool__(self):
        user = self.__get_user()
        return user is not None

    __nonzero__ = __bool__

    def __str__(self):
        return str(self.__get_user())

    def __unicode__(self):
        return to_unicode(self.__get_user())

    def __dir__(self):
        return dir(self.__get_user())

    def __getattr__(self, name):
        return getattr(self.__get_user(), name)

    def __setattr__(self, name, value):
        setattr(self.__get_user(), name, value)

    def __delattr__(self, name):
        delattr(self.__get_user(), name)

    def __hash__(self):
        return hash(self.__get_user())

    def __call__(self, *args, **kwargs):
        return self.__get_user()(*args, **kwargs)

    def __eq__(self, other):
        return self.__get_user() == other

    def __ne__(self, other):
        return self.__get_user() != other

    def __setitem__(self, key, value):
        self.__get_user()[key] = value

    def __delitem__(self, key):
        del self.__get_user()[key]

    def __lt__(self, other):
        return self.__get_user() < other

    def __le__(self, other):
        return self.__get_user() <= other

    def __gt__(self, other):
        return self.__get_user() > other

    def __ge__(self, other):
        return self.__get_user() >= other

    def __getitem__(self, i):
        return self.__get_user()[i]

    def __iter__(self):
        return iter(self.__get_user())

    def __contains__(self, i):
        return i in self.__get_user()

    def __add__(self, other):
        return self.__get_user() + other

    def __sub__(self, other):
        return self.__get_user() - other

    def __mul__(self, other):
        return self.__get_user() * other

    def __floordiv__(self, other):
        return self.__get_user() // other

    def __mod__(self, other):
        return self.__get_user() % other

    def __divmod__(self, other):
        return self.__get_user().__divmod__(other)

    def __pow__(self, other):
        return self.__get_user() ** other

    def __lshift__(self, other):
        return self.__get_user() << other

    def __rshift__(self, other):
        return self.__get_user() >> other

    def __and__(self, other):
        return self.__get_user() & other

    def __xor__(self, other):
        return self.__get_user() ^ other

    def __or__(self, other):
        return self.__get_user() | other

    def __div__(self, other):
        return self.__get_user().__div__(other)

    def __truediv__(self, other):
        return self.__get_user().__truediv__(other)

    def __neg__(self):
        return -(self.__get_user())

    def __pos__(self):
        return +(self.__get_user())

    def __abs__(self):
        return abs(self.__get_user())

    def __len__(self):
        return len(self.__get_user())

    def __invert__(self):
        return ~(self.__get_user())

    def __complex__(self):
        return complex(self.__get_user())

    def __int__(self):
        return int(self.__get_user())

    def __float__(self):
        return float(self.__get_user())

    def __enter__(self):
        return self.__get_user().__enter__()

    def __exit__(self, *args, **kwargs):
        return self.__get_user().__exit__(*args, **kwargs)
