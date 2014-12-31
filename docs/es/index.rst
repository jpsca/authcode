:orphan:

=============================================
Authcode
=============================================

.. container:: lead

    Authocode es una solución limpia para la **autenticación** y **autorización** de *aplicaciones web* en Python.

    Brevemente, la autenticación es verificar que un usuario es quien dice ser, y la autorización es manejar lo que un usuario autenticado tiene permiso para hacer

Depende de que uses SQLAlchemy, pero no necesita de ningún *framework* web específico.


Ventajas
--------------------------------------------

- Independiente de cualquier framework.
- Modelos de Usuario y Roles incluidos, pero personalizables.
- Incluye vistas y plantillas (opcionales) listas para autenticarse o restablecer tu contraseña.
- Permite varios modelos de usuarios en paralelo.
- Usa los algoritmos de *hashing* de contraseñas más seguros.
- Auto-actualiza tus hashes de contraseñas antiguos (cuando el usuario se autentica).
- Fácil de usar con otras formas de autenticación (eg: Facebook).
- Protección contra los ataques por Cross Site Request Forgery (CSRF).
- Compatible con Python 2.6 y 2.7, Pypy y Python 3.3 o posterior.

.. include:: contents.rst.inc
