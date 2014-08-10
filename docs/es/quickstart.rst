.. _quickstart:

=============================================
Introducción a Authcode
=============================================

.. container:: lead

    Esta guía cubre lo que necesitas saber para empezar a usar Authcode.


Requisitos
=============================================

Aunque Authcode no depende de ningún framework web específico, si necesita que exista cierta infraestructura básica para funcionar. :

- Un objeto de ``sesion`` con una interfaz similar a la de un diccionario.
    Debe permitir hacer cosas como ``sesion['foo'] = 'bar`` y ``sesion.get('foo', None)``.

- Un objeto ``request`` que represente a la solicitud de página actual. Por ahora solo soporta el formato de `Werkzeug`_ (Flask) y `WebOb`_ (Pyramid), pero es fácilmente extensible para trabajar con otros como el de `CherryPy`_.

- Un argumento ``db`` usado para comunicarse con SQLAlchemy. Si estás usando `SQLAlchemy-Wrapper`_ o `Flask-SQLAlchemy`_ ya tienes uno. Si no, solo pasa un objeto propio con el modelo base en ``db.Model`` y la sesión de SQLAlchemy en ``db.session``.


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

