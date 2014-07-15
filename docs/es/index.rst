:orphan:


Authcode es una solución elegante para manejar **autenticación** (verificae que un usuario sea quien dice ser) y **autorización** (determina lo que un usuario autenticado tiene permiso para hacer0 en aplicaciones web en Python.

Esta biblioteca depende de que uses SQLAlchemy, pero no de algún *framework* web específico.


Ventajas
--------

- Independiente de un framework
- Usa los algoritmos de *hashing* de contraseñas más seguros
- Modelos de Usuario y Roles incluidos, pero personalizables.
- Incluye vistas y plantillas (opcionales) listas para hacer login y restablecer contraseña
- Auto-actualiza tus hashes de contraseñas antiguos (cuando el usuario se loguea)
- Muy fácil de agregar otras formas de autenticación (eg: Facebook)
- Protección contra los ataques por Cross Site Request Forgery (CSRF).
- Compatible with Python 2.7, 3.4+ y Pypy.

.. include:: contents.rst.inc

