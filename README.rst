
===========================
Authcode
===========================

Awesome authentication code for Flask and Bottle web apps.

.. image:: https://travis-ci.org/jpscaletti/authcode.svg?branch=master
   :target: https://travis-ci.org/jpscaletti/Authcode
   :alt: Build Status


Authcode is a clean solution for both authentication and authorization of Python web applications. Briefly, authentication verifies a user is who they claim to be, and authorization determines what an authenticated user is allowed to do.

It uses SQLAlchemy models and works out of the box with `Flask <http://flask.pocoo.org/>`_ and `Bottle <http://bottlepy.org/>`_, but can be adapted to use it with other web frameworks.


(1) Create

.. code:: python

    auth = authcode.Auth(SECRET_KEY, db=db, roles=True)
    User = auth.User
    Role = auth.Role

(2) Setup

.. code:: python

    authcode.setup_for_flask(auth, app)

(3) Protect

.. code:: python

    @app.route('/')
    @auth.protected()
    def index():
        return u'Welcome ' + g.user.login

    @app.route('/top-secret/')
    @auth.protected(role='007')
    def top_secret():
        return 'For your eyes only'


Highlights
======================

-  Default but fully customizable User & Role models.
-  Ready to use authentication views and templates.
-  Support multiple users models at the same time
-  Password-reset tokens.
-  Cross Site Request Forgery (CSRF) protection.
-  Uses the most secure hash algorithms.
-  Auto-update of old password hashes.
-  Compatible with Python 2.7, 3.4+ and Pypy.


TODO
======================

- More documentation (always!)
    - Automatic views: how to use and customize
    - Manual views
- Examples:
    - Default
    - Twitter + login/password example
    - Mozilla Persona example?
- Tutorials, etc.
- Code:
    - MultiAuth tests


Contributing
======================

#. Check for `open issues <https://github.com/jpscaletti/Authcode/issues>`_ or open
   a fresh issue to start a discussion around a feature idea or a bug.
#. Fork the `Authcode repository on Github <https://github.com/jpscaletti/Authcode>`_
   to start making your changes.
#. Write a test which shows that the bug was fixed or that the feature works
   as expected.
#. Send a pull request and bug the maintainer until it gets merged and published.
   :) Make sure to add yourself to ``AUTHORS``.


Run the tests
======================

We use some external dependencies, listed in ``requirements_tests.txt``::

    $  pip install -r requirements-tests.txt
    $  python setup.py install

To run the tests in your current Python version do::

    $  make test

To run them in every supported Python version do::

    $  tox

It's also neccesary to run the coverage report to make sure all lines of code
are touch by the tests::

    $  make coverage

Our test suite `runs continuously on Travis CI <https://travis-ci.org/jpscaletti/Authcode>`_ with every update.

______

:copyright: `Juan-Pablo Scaletti <http://jpscaletti.com>`_.
:license: MIT, see LICENSE for more details.
