.. _quickstart:

=============================================
Introducción a Authcode
=============================================

.. container:: lead

    Esta guía cubre lo que necesitas saber para empezar a usar Authcode.


Requisitos
=============================================

Aunque Authcode no depende de ningún framework web específico, si necesita que exista cierta infraestructura básica para funcionar:

- Una ``sesion`` con una interfaz similar a la de un diccionario.
    Debe permitir hacer cosas como ``sesion['foo'] = 'bar`` y ``sesion.get('foo', None)``. Tu framework ya debe de tener alguna. O si no puedes usar la de `Beaker`_.

- Un objeto ``request`` que represente a la solicitud de página actual. Por ahora solo soporta el formato de `Werkzeug`_ (Flask) y `WebOb`_ (Pyramid), pero es fácilmente extensible para trabajar con otros, como el de `CherryPy`_ por ejemplo.

- Un argumento ``db`` usado para comunicarse con SQLAlchemy. Si estás usando `SQLAlchemy-Wrapper`_ o `Flask-SQLAlchemy`_ ya tienes uno.

.. _Beaker: http://beaker.readthedocs.org/
.. _Werkzeug: http://werkzeug.pocoo.org/
.. _WebOb: http://webob.org/
.. _CherryPy: http://www.cherrypy.org/
.. _SQLAlchemy-Wrapper: https://github.com/lucuma/SQLAlchemy-Wrapper/
.. _Flask-SQLAlchemy: http://pythonhosted.org/Flask-SQLAlchemy/




Meh
=============================================

.. code-block:: python

    import authcode
    from flask.ext.sqlalchemy import SQLAlchemy

    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///'
    db = SQLAlchemy(app)

    auth = authcode.Auth(SECRET_KEY, db=db)
    authcode.setup_for_flask(auth, app)
    User = auth.User


.. [#] Usar `SQLAlchemy-Wrapper`_ te ahorrará mucho trabajo, independientemente si usas o no Authcode. En serio, dale una mirada.