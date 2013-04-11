Password hashing
================

AuthCode delegates all the heavy lifting of password hashing to the
excellent `"passlib" <http://pythonhosted.org/passlib/>`_.

The hasher used to encrypt new passwords can be configured with the
``hash`` parameter at initialization time. For real security, it has to
be one of these options:
`"bcrypt" <http://pythonhosted.org/passlib/lib/passlib.hash.bcrypt.html>`_,
`"pbkdf2\_sha512" <http://pythonhosted.org/passlib/lib/passlib.hash.pbkdf2_digest.html#passlib.hash.pbkdf2_sha512l>`_
or
`"sha512\_crypt" <http://pythonhosted.org/passlib/lib/passlib.hash.sha512_crypt.html>`_.

Example:

.. code:: python

    >>> auth = Auth(secret, hash='bcrypt', ...)
    >>> auth.hash_password('Awesome')
    '$2a$12$LfgaavA5AzRmzdxbUxsS3O0dAxSOoweTOsOmy/GsjJMGVa1O59362'

All three password hashers share the following properties:

-  no known vulnerabilties.
-  based on documented & widely reviewed algorithms.
-  basic algorithm has seen heavy scrutiny and use for at least 10
   years.
-  public-domain or BSD-licensed reference implementations available.
-  in use across a number of OSes and/or a wide variety of applications.
-  variable rounds for configuring flexible cpu cost on a per-hash
   basis.
-  at least 96 bits of salt.

If you don't define a hash algorithm, AuthCode will choose the best
available at the time (so it'll be ``bcrypt`` or ``pbkdf2_sha512``).

You can also define a variable number of ``rounds``. This is a positive
integer that control the number of operations and how long it takes to
hash a password. The default choice should be secure enough for the
average system. Each hasher has specific requirements so check its
documentation if you want to change this value.

Updating the hashes
-------------------

As computing power increases, mature applications have to update the
existing password hashes with a new algorithm or to raise the time-cost
settings. However, the whole point of store hashes is to make impossible
to recover the original passwords, so you can't simply re-hash them.

AuthCode is prepared to deal with the future. You just define a new
supported hasher and/or number of rounds in the settings and, when the
user logs in again, her password hash will be automatically updated to
new format and stored.

(You can also turn this behaviour off by setting the ``update_hash``
parameter to ``False``).

The library supports changing between the three valid hashers but also
to read hashes in the `"django\_\*" family of
formats <http://pythonhosted.org/passlib/lib/passlib.hash.django_std.html>`_
and `generic hexadecimal
digests <http://pythonhosted.org/passlib/lib/passlib.hash.hex_digests.html>`_.
Click on them for more information.

Dealing with unsupported hash formats
-------------------------------------

You can still migrate your exisiting password hashes even if they are in
an unsupported format. For that, you overwrite the
``Auth.verify_and_update`` with custom code to deal with your hashes.
Don't forget to call the original method if the hash is already in the
new format.

.. code:: python

    def verify_and_update(secret, hashed):
        if is_old_format(hashed):
            ok = verify_old_hash(secret, hashed)
            if ok:
                return True, auth.hash_password(secret)
            return False, None

        return auth._verify_and_update(secret, hashed)

    auth._verify_and_update = auth.verify_and_update
    auth.verify_and_update = verify_and_update

