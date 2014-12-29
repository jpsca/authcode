# coding=utf-8
"""
    ==========
    Authcode
    ==========

    Awesome authentication code

    :copyright: © 2012-2014 by `Juan Pablo Scaletti <http://jpscaletti.com>`_.
    :license: MIT, see LICENSE for more details.

"""
from .auth import Auth, WrongHashAlgorithm  # noqa
from .setups import setup_for_flask, setup_for_shake  # noqa


__version__ = '1.1.1'
