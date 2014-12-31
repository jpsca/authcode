.. _quickstart:

=============================================
Inicio rápido
=============================================

.. container:: lead

    Esta guía cubre lo que necesitas saber para empezar a usar Authcode.


Para usar Authcode bastan solo tres pasos.


1. Crear un objeto Auth
----------------------------------------------

Hay varios parámetros que puedes usar para configurarlo, pero lo mínimo necesario es una clave secreta y una conexión a SQLAlchemy.

.. code-block:: python

    auth = authcode.Auth(SECRET_KEY, db=db)
    User = auth.User

El objeto ``db`` que es te da `SQLAlchemy_Wrapper <https://github.com/lucuma/SQLAlchemy-Wrapper/>`_ [1]_ o `Flask_SQLAlchemy <http://pythonhosted.org/Flask-SQLAlchemy/>`_.

``auth.User`` es el modelo de usuario generado automáticamente por Authcode. Necesitarás esa referencia para crear usuarios o conectarlos a tus otros modelos.

.. tip::

    ¿No tienes un objeto ``db`` por que estás usando SQLAlchemy diréctamente? [1]_
    **¡No lo hagas!** Incluso su documentación te recomienda que uses una capa intermedia en aplicaciones web.

    Si realmente **necesitas** hacerlo, lee esta sección: :ref:`advanced.naked_sqlalchemy` para saber como.

2. Ajustarlo a tu framework
----------------------------------------------

Lo siguiente es ajustar el objeto Auuth recién creado al framework web que estés usando. Por ejemplo, para Flask:

.. code-block:: python

    authcode.setup_for_flask(auth, app)

Esta función de setup se encarga de terminar de conectar a Authcode con las peculiaridades del framework que uses, por ejemplo como interpretar las plantillas, agregar vistas y esas cosas. Por ahora estos son las framework incluidos (lo que no significa que no puedas agregar el tuyo):

* `Flask <http://flask.pocoo.org/>`_ (``setup_for_flask``)
* *¡Más próximamente!*


3. Proteger tus vistas
----------------------------------------------

Finalmente, usas ``auth.protected`` para decorar las vistas que quieres que sean solo accesibles para usuarios.

.. code-block:: python

    @app.route('/')
    @auth.protected()
    def index():
        ...

.. note::

    Nota que el decorador está siendo llamado (tiene un par de paréntesis al final de la línea). Estos son necesarios, si los olvidas tendrás un error.

.. warning:: ¡Cuidado!
    Ten mucho cuidado en poner el decorador de autenticación **después** del de la ruta o, de otro modo, tus vistas quedarán desprotegidas.

Puedes ver este ejemplo completo en https://github.com/lucuma/authcode/tree/master/examples/minimal.

Authcode genera automáticamente vistas para inicar sesión, salir y recuperar tu contraseña, así que cuando intentes visitar la página del ejemplo, te redirigirá a otra para ingresar tu usuario y contraseña (en el ejemplo ambos son “authcode”).

.. figure:: _static/loginpage.png
   :align: center

   Página estándar de inicio de sesión.

Puedes ver que esa página también tiene un enlace a otra para recuperar tu contraseña; El método es el estándar: escribes tu nombre de usuario y Authcode te envía un correo con un enlace especial para que elijas una nueva contraseña.

Para que esto funciona, al ejemplo le hace falta una forma de enviar el email, eso es una funcionalidad que tiene que darle tu aplicación [#]_. Por ejemplo:

.. code-block:: python

    def send_auth_email(user, subject, msg):
        try:
            mailer.send(
                subject=subject,
                from_email=config.MAILER_FROM,
                to=user.email,
                html=msg
            )
        except Exception as e:
            print(e)

    authcode.setup_for_flask(auth, app, send_email=send_auth_email)

La función que le pasas a ``send_email`` toma como argumentos el usuario que quiere recuperar su contraseña, el título del email y el cuerpo del mensaje (por defecto en HTML). Por supuesto que tienes que tener un email asociado al usuario, de modo que o bien usas su email como nombre de usuario o agregas un campo de email usando un *mixin* como se describe en la siguiente sección (:ref:`authentication`).


.. [#] `SQLAlchemy-Wrapper`_ te ahorrará mucho trabajo al tratar con ``SQLAlchemy``, independientemente si usas o no Authcode. En serio, dale una mirada.

.. [#] o también puedes desactivarla por completo en las opciones de configuración.
