.. _installation:

Instalación
============

Authcode depende de que estés usando SQLAlchmey en tu aplicación web.
Tambien, aunque no depende de ningún framework web específico, necesita que exista cierta infraestructura básica para funcionar corréctamente:

- Un objeto de ``sesion`` con una interfaz similar a la de un diccionario.
    Debe permitir hacer cosas como ``sesion['foo'] = 'bar`` y ``sesion.get('foo', None)``.

- Un objeto ``request`` que represente a la solicitud de página actual. Por ahora solo soporta el formato de `Werkzeug`_ y `WebOb`_, pero es fácilmente extensible para trabajar con otros como el de `CherryPy`_.

- Un argumento ``db`` usado para comunicarse con SQLAlchemy. Si estás usando `Flask-SQLAlchemy`_ o `orm`_ ya tienes uno. Si no, solo pasa un objeto propio con el modelo base en ``db.Model`` y la sesión de SQLAlchemy en ``db.session``.




.. _Werkzeug: http://werkzeug.pocoo.org/
.. _WebOb: http://webob.org/
.. _CherryPy: http://www.cherrypy.org/
.. _Flask-SQLAlchemy: http://pythonhosted.org/Flask-SQLAlchemy/
.. _orm: https://github.com/lucuma/orm/
