
===========================
Authcode
===========================

Awesome authentication code.

.. image:: https://travis-ci.org/lucuma/Authcode.png
   :target: https://travis-ci.org/lucuma/Authcode
   :alt: Build Status

.. image:: https://coveralls.io/repos/lucuma/Authcode/badge.png
   :target: https://coveralls.io/r/lucuma/Authcode
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
-  Support multiple users models at the same time
-  Compatible with Python 2.7, 3.4+ and Pypy.

TODO
======================

* More documentation (always!)
    - English documentation
    - Automatic views: how to use and customize
    - Manual views

    - Examples:
        - Twitter + login/password example
        - Mozilla Persona example
        - Login/Password + Mozilla Persona example

    - Tutorials, etc.

* Code:
    - Setup functions for CherryPy, Pyramid, bottle, webpy, etc.
    - <Your web framework here> setup and tests
    - MultiAuth tests



Community & support
======================

Issue tracker: https://github.com/lucuma/Authcode/issues

______

:copyright: © 2012-2015 by `Juan-Pablo Scaletti <http://jpscaletti.com>`_.
:license: MIT, see LICENSE for more details.
