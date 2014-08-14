
===========================
Authcode
===========================

Awesome authentication code.

.. image:: https://travis-ci.org/lucuma/authcode.png
   :target: https://travis-ci.org/lucuma/authcode
   :alt: Build Status

.. image:: https://coveralls.io/repos/lucuma/authcode/badge.png
   :target: https://coveralls.io/r/lucuma/authcode
   :alt: Tests coverage status


Authcode is a clean solution for both authentication and authorization of Python web applications. Briefly, authentication verifies a user is who they claim to be, and authorization determines what an authenticated user is allowed to do.

It uses SQLAlchemy models but does not depends of any specific web framework.

Features
======================

-  Framework independent
-  Uses the most secure hash algorithms.
-  Default but fully customizable User & Role models.
-  Ready to use authentication views and templates.
-  Auto-update of old password hashes.
-  Password-reset tokens.
-  Cross Site Request Forgery (CSRF) protection.
-  Compatible with Python 2.7, 3.4+ and Pypy.

TODO
======================

* Better documentation

* Code:
    - CherryPy setup and tests
    - Pyramid setup and tests

* Examples:
    - Nicer templates/CSS
    - Upload examples to Heroku
    - Login/password example
    - Twitter + login/password example
    - Mozilla Persona example
    - Login/Password + Mozilla Persona example


Community & support
======================

Issue tracker: https://github.com/lucuma/authcode/issues

______

:copyright: © 2012-2014 by `Juan-Pablo Scaletti <http://jpscaletti.com>`_.
:license: MIT, see LICENSE for more details.
