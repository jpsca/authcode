.. _advanced:

=============================================
Patrones avanzados
=============================================


.. _advanced.backends:

Agregar backends de autenticación
=============================================

Las credenciales no tienen por que ser siempre el usuario y contraseña. De hecho, Authcode te permite manejar varios tipos de credenciales en paralelo.

Para autenticar a un usuario, ``auth.authenticate`` recibe un diccionario con los datos que le envía la vista y prueba los *backends* registrados, en orden, hasta que uno devuelva un usuario.

Authcode incluye dos *backends* por defecto: ``auth.auth_password``, que busca credenciales llamadas “login” y “password”; y ``auth.auth_token``, que busca una credencial llamada “token” con un formato especial (es lo que usa el sistema de restablecer contraseña).

También puedes agregar tus propios backends; Por ejemplo este es el código necesario para que un usuario pueda usar su nombre de usuario **o** su email según prefiera:

.. code-block:: python

    def authenticate_by_email(credentials):
        credentials = credentials.copy()
        email = credentials.get('login')
        secret = credentials.get('password')
        if email is None or secret is None:
            return None

        user = User.by_email(email)
        if not user:
            return None

        credentials['login'] = user.login
        return auth.auth_password(credentials)


    # Authcode is awesome!!
    auth.backends.append(authenticate_by_email)

Este ejemplo simplemente busca al usuario por su email y si lo encuentra, llama al método estándar de autenticación por login/password para que se encargue de validar la contraseña.

Puedes usar este patrón para integrarte con otros metodos de autenticación de un solo paso como `LDAP <http://es.wikipedia.org/wiki/LDAP>`_, sistemas propios, etc. No sirve, sin embargo, para métodos que necesitan varios pasos, como OAuth; Para esos, sigue leyendo.


.. _advanced.oauth:

OAuth
=============================================

Para autenticar a tus usuarios por OAuth (via Twitter o Facebook, etc.), la idea es delegar el proceso de autenticación a otra biblioteca y, una vez identificado el usuario, loguearlo con ``auth.login(user)`` usar Authcode para el resto.

Este ejemplo usa `Flask-OAuthlib <https://flask-oauthlib.readthedocs.org/en/latest/>`_ (revisa su documentación para que el código de abajo tenga sentido):

.. code-block:: python

    oauth = OAuth()
    twitter = oauth.remote_app(
        'twitter',
        base_url='https://api.twitter.com/1/',
        request_token_url='https://api.twitter.com/oauth/request_token',
        access_token_url='https://api.twitter.com/oauth/access_token',
        authorize_url='https://api.twitter.com/oauth/authorize',
        consumer_key=settings.TWITTER_KEY,
        consumer_secret=settings.TWITTER_SECRET
    )

    @app.route('/sign-in/twitter/')
    def twitter_login():
        next = request.args.get('next') or url_for('profile')
        if 'twitter_token' in session:
            del session['twitter_token']
        return twitter.authorize(
            callback=url_for('twitter_authorized', next=next)
        )

    @app.route('/sign-in/twitter/authorized/')
    @twitter.authorized_handler
    def twitter_authorized(resp):
        if resp is None:
            flash(u'You denied the request to sign in.')
            return redirect(url_for('sign_in'))

        session['twitter_token'] = resp['oauth_token']

        # >>> resp
        # {
        #     "oauth_token_secret": "...",
        #     "oauth_token": "...",
        #     "user_id": "123...",
        #     "screen_name": "lucumalabs"
        # }
        user = db.query(User).filter(User.twitter_id == resp['user_id']).first()

        if not user:  # new user!
            if g.user:
                user = g.user
            else:
                login = get_unique_login(resp['screen_name'])
                user = User(login=login)
                db.add(user)
            user.twitter_id = resp['user_id']

        user.last_sign_in = datetime.utcnow()
        # in any case we update the authentication token in the db
        # In case the user temporarily revoked access we will have
        # new tokens here.
        user.twitter_username = resp['screen_name']
        user.twitter_token = resp['oauth_token']
        user.twitter_secret = resp['oauth_token_secret']
        # don't forget to commit **before** doing ``auth.login(user)`
        db.commit()

        auth.login(user)
        next = request.args.get('next') or url_for('profile')
        return redirect(next)

    @twitter.tokengetter
    def get_twitter_token(token=None):
        return session.get('twitter_token')

Puedes ver el ejemplo completo corriendo aquí: `http://authcode-tw-fb.herokuapp.com/ <http://authcode-tw-fb.herokuapp.com/>`_

El código fuente del ejemplo completo está en https://github.com/lucuma/Authcode/tree/master/examples/twitter_or_facebook.


.. _advanced.multiauth:

Más de un Auth al mismo tiempo
=============================================

En muchos casos, un solo Auth y la flexibilidad que te dan los roles, es más que suficiente. Para algunas aplicaciones complejas, sin embargo, tiene sentido de tener sistemas de autenticación/autorización en paralelo, con tablas de usuarios diferentes, vistas separadas, etc.


Auth excluyentes
---------------------------------------------

Para lograr dos o más Auth **en que los usuarios de diferentes Auth nunca deban estar logueados en la misma sesión al mismo tiempo**, solo necesitas pasarle a Authocode un argumento ``prefix``:

.. code-block:: python

    Auth(
        config.SECRET_KEY, db=db, UserMixin=UserMixin, roles=True,
        prefix='bo', **AUTH_SETTINGS
    )


Ese prefijo se usará para:

1. Cambiar el nombre del modelo de usuario (a la clase, no a la tabla) a ``PrefijoUser`` (por ejemplo, ``BoUser``, y el de roles (si lo usas) a ``PrefijoRole``. Esto es necesario porque SQLAlchemy no permite que dos modelos se llamen igual, aunque sus tablas ya tengan nombres diferentes.
2. Darle ese prefijo a los nombres de las vistas automáticas (esto es, si usas vistas automáticas). Por ejemplo, ``bo_auth_sign_in`` en vez de ``auth_sign_in``.
3. Darle ese prefijo a las URLs de esas vistas: ``/bo/sign-in/`` en vez de ``/sign-in/``.

Todo o parte de esto puedes definirlo manualmente, si lo necesitas, con las opciones:
``users_model_name``, ``roles_model_name``, ``views_prefix``, ``url_sign_in``, ``url_sign_out``, ``url_reset_password`` y ``url_change_password``.

También podrías queres definir plantillas para las vistas diferentes de las por defecto, el título del email de recuperación de contraseña, etc.

.. code-block:: python

    # --- AUTH 1 ---

    AUTH_SETTINGS = {
        ...
    }

    auth = Auth(
        config.SECRET_KEY, db=db, UserMixin=UserMixin, roles=True,
        **AUTH_SETTINGS
    )
    setup_for_flask(auth, app, send_email=send_auth_email)

    User = auth.User
    Role = auth.Role

    # --- AUTH 2 ---

    BOAUTH_SETTINGS = {
        'template_sign_in': 'backoffice/auth/sign-in.html',
        'template_sign_out': None,
        'template_reset': 'backoffice/auth/reset-password.html',
        'template_change_password': 'backoffice/auth/change-password.html',
        'template_reset_email': 'emails/reset-password-bo.html',
        'reset_email_subject': u'Restablecer tu contraseña de BackOffice',

        ...
    }

    boauth = Auth(
        config.SECRET_KEY, db=db, roles=False, UserMixin=BoUserMixin,
        prefix='bo', **BOAUTH_SETTINGS
    )
    setup_for_flask(boauth, app, send_email=send_auth_email)

    BoUser = boauth.User


Como ves, cada Auth puede tener distinta configuración o compartir cosas como la llave secreta, la función de envío de emails, etc.

En el ejemplo, como he definido el prefijo como `bo_``, las vistas automáticas se llamarán ``bo_auth_sign_in``, ``bo_auth_sign_out``, ``bo_auth_reset_password`` y ``bo_auth_change_password``.


Auth en paralelo
---------------------------------------------

El otro caso posible es que necesites que los **usuarios de diferentes Auth puedan mantenerse logueados en la misma sesión al mismo tiempo**. Podría ser que se trate de un super-admin que deba poder tomar la identidad de otros usuarios a voluntad, o un caso similar.

Solo necesitas hacer tres cosas más para lograrlo:

#. Elegir el nombre bajo el que se guardará el identificador de usuario de este Auth en la sesión (opción ``session_key``).
#. Elegir un nombre con el que el usuario logueado se guardará. (opción ``user_name``)
#. Asegurarte que la sesión no se destruye por completo al cerrar sesión en alguna de las Auth.

.. code-block:: python
   :emphasize-lines: 4,21,22,23,28,29

    # --- AUTH 1 ---

    AUTH_SETTINGS = {
        clear_session_on_logout: False,
        ...
    }

    auth = Auth(
        config.SECRET_KEY, db=db, UserMixin=UserMixin, roles=True,
        **AUTH_SETTINGS
    )
    setup_for_flask(auth, app, send_email=send_auth_email)

    User = auth.User
    Role = auth.Role

    # --- AUTH 2 ---

    BOAUTH_SETTINGS = {

        'session_key': '_bohm',
        'user_name': 'bouser',
        'clear_session_on_logout': False,
        ...
    }

    boauth = Auth(
        config.SECRET_KEY, db=db, roles=False, UserMixin=BoUserMixin,
        prefix='bo', **BOAUTH_SETTINGS
    )
    setup_for_flask(boauth, app, send_email=send_auth_email)

    BoUser = boauth.User

De esta forma, encontrarás al usuario logueado en el primer Auth en ``g.user`` y el de la segunda en ``g.bouser``.

Asi mismo, el argumento ``clear_session_on_logout`` hará que al cerrar sesión en cualquiera de los Auth, solo se borre el identificador de usuario que corresponda, en vez de borrar la sesión por completo.


.. _advanced.custom_setup
..
    Un ``setup_for_`` personalizado
    =============================================

    TO DO

    Aunque Authcode no depende de ningún framework web específico, si necesita que exista cierta infraestructura básica para funcionar:

    - Una ``session`` con una interfaz similar a la de un diccionario.
        Debe permitir hacer cosas como ``session['foo'] = 'bar`` y ``session.get('foo', None)``. Tu framework ya debe de tener alguna. O si no puedes usar la de `Beaker`_.

    - Un objeto ``request`` que represente a la solicitud de página actual. Por ahora solo soporta el formato de `Werkzeug`_ (Flask), y `Bottle`_ (Pyramid).

    - Un argumento ``db`` usado para comunicarse con SQLAlchemy. Si estás usando `SQLAlchemy_Wrapper`_ [#]_ o `Flask_SQLAlchemy`_ ya tienes uno.

    .. _Beaker: http://beaker.readthedocs.org/
    .. _Werkzeug: http://werkzeug.pocoo.org/
    .. _Bottle: http://bottlepy.org/
    .. _SQLAlchemy_Wrapper: https://github.com/lucuma/SQLAlchemy-Wrapper/
    .. _Flask_SQLAlchemy: http://pythonhosted.org/Flask-SQLAlchemy/


.. _advanced.naked_sqlalchemy:

Reemplazando al objeto db
=============================================

¿Estás usando SQLAlchemy diréctamente y no tienes un objeto ``db`` para inicializar ``Auth``? Simplemente usa una clase similar a esta:

.. code-block:: python

    from sqlalchemy import create_engine
    from sqlalchemy.ext.declarative import declarative_base
    from sqlalchemy.orm import scoped_session, sessionmaker

    engine = create_engine('sqlite://', ...)

    class DB(object):
        Session = scoped_session(sessionmaker(bind=engine, ...))
        Model = declarative_base()

        @property
        def session(self):
            return self.Session()

        def shutdown(response=None):
            self.session.remove()
            return response

    # y finalmente...
    db = DB()
    auth = Authcode.Auth(SECRET_KEY, db=db)

*No olvides conectarlo a tu framework para que, al final de cada ciclo de request, refresque la sesión llamando a ``db.shutdown()``*
