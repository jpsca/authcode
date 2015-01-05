
===========================
Authcode
===========================

Awesome authentication code.

.. image:: https://travis-ci.org/lucuma/authcode.svg?branch=master
   :target: https://travis-ci.org/lucuma/Authcode
   :alt: Build Status

.. image:: https://coveralls.io/repos/lucuma/authcode/badge.png?branch=master
   :target: https://coveralls.io/r/lucuma/Authcode
   :alt: Tests coverage status


Authcode is a clean solution for both authentication and authorization of Python web applications. Briefly, authentication verifies a user is who they claim to be, and authorization determines what an authenticated user is allowed to do.

It uses SQLAlchemy models and works out of the box with Flask, web.py and CherryPy (needs more testing), but can be adapted to use it with many other web frameworks.


Features
======================

-  Framework independent
-  Default but fully customizable User & Role models.
-  Ready to use authentication views and templates.
-  Password-reset tokens.
-  Cross Site Request Forgery (CSRF) protection.
-  Support multiple users models at the same time
-  Uses the most secure hash algorithms.
-  Auto-update of old password hashes.
-  Compatible with Python 2.7, 3.4+ and Pypy.


TODO
======================

* More documentation (always!)
    - English documentation
    - Automatic views: how to use and customize
    - Manual views

    - Examples:
        - Default
        - Twitter + login/password example
        - Mozilla Persona example
        - Login/Password + Mozilla Persona example

    - Tutorials, etc.

* Code:
    - Test setup functions for CherryPy, bottle, webpy, etc.
    - <Your web framework here> setup and tests
    - MultiAuth tests


Contributing
======================

1. Check for `open issues <https://github.com/lucuma/Authcode/issues>`_ or open a fresh issue to start a discussion around a feature idea or a bug..
2. Fork the `Authcode repository on Github <https://github.com/lucuma/Authcode>`_ to start making your changes.
3. Write a test which shows that the bug was fixed or that the feature works as expected.
4. Send a pull request and bug the maintainer until it gets merged and published. :) Make sure to add yourself to ``AUTHORS``.


Run the tests
======================

We use some external dependencies, listed in ``requirements_tests.txt``:

    $  pip install -r requirements_tests.txt
    $  python setup.py install

To run the tests in your current Python version do::

    $  make test

To run them in every supported Python version do::

    $  tox

Our test suite `runs continuously on Travis CI <https://travis-ci.org/lucuma/Authcode>`_ with every update.

______

:copyright: © `Juan-Pablo Scaletti <http://jpscaletti.com>`_.
:license: MIT, see LICENSE for more details.
