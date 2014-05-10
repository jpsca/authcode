# coding=utf-8


class WrongHashAlgorithm(Exception):

    def __str__(self):
        return ('Only `bcrypt` (requires py-bcrypt), `pbkdf2_sha512` and `sha512_crypt` are valid hash values.\nAuthCode can *read* many other hash formats but, for security reasons, only generates hashes with these three algorithms.\nOlder hashes will be automatically converted to the new algorithm when the user logs in.')