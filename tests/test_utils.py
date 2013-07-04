# -*- coding: utf-8 -*-
import os
from datetime import datetime

from authcode import utils


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

