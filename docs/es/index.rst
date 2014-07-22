:orphan:

=============================================
Authcode
=============================================

.. container:: lead

    Authcode es una biblioteca para manejar de forma flexible la **autenticación** —verificar que un usuario sea quien dice ser— y **autorización** —lo que un usuario autenticado tiene permiso para hacer— en *aplicaciones web* en Python.

Depende de que uses SQLAlchemy, pero no necesita de ningún *framework* web específico.


Ventajas
--------------------------------------------

- Independiente de cualquier framework
- Usa los algoritmos de *hashing* de contraseñas más seguros
- Modelos de Usuario y Roles incluidos, pero personalizables.
- Incluye vistas y plantillas (opcionales) listas para hacer login y restablecer contraseña
- Auto-actualiza tus hashes de contraseñas antiguos (cuando el usuario se loguea)
- Muy fácil de agregar otras formas de autenticación (eg: Facebook)
- Protección contra los ataques por Cross Site Request Forgery (CSRF).
- Compatible with Python 2.6 y 2.7; Python 3.3+ y Pypy.

.. include:: contents.rst.inc

