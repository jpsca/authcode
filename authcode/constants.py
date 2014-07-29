# coding=utf-8


DEFAULT_HASHER = 'pbkdf2_sha512'

VALID_HASHERS = [
    'sha512_crypt', 'pbkdf2_sha512', 'bcrypt',
    'sha256_crypt', 'pbkdf2_sha256', 'pbkdf2_sha1',
    'ldap_sha512_crypt', 'ldap_sha256_crypt',
    'ldap_pbkdf2_sha512', 'ldap_pbkdf2_sha256',
    'ldap_bcrypt',
]

DEPRECATED_HASHERS = [
    'django_pbkdf2_sha256', 'django_pbkdf2_sha1', 'django_bcrypt',
    'django_salted_sha1', 'django_salted_md5', 'django_des_crypt',
    'hex_sha512', 'hex_sha256', 'hex_sha1', 'hex_md5', 'hex_md4'
]

MIN_SECRET_LENGTH = 15

TEMPLATES = {
    'sign_in': 'sign-in.html',
    'sign_out': None,
    'reset': 'reset-password.html',
    'reset_email': 'reset-password-email.html',
    'change_password': 'change-password.html',
}

WRONG_HASH_MESSAGE = """Invalid hash format.
Authcode can *read* many hash formats but, for security reasons,
only generates hashes with a limited subset of them.

Valid formats
-------------------------------
- {0}

Readable but deprecated formats
-------------------------------
All of the valid formats plus
- {1}

Readable but invalid hashes will be automatically converted to the
new format when the user logs in.
""".format(
    '\n - '.join(VALID_HASHERS),
    '\n - '.join(DEPRECATED_HASHERS)
)
