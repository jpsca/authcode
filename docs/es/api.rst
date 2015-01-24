.. _api:

=============================================
API
=============================================

.. container:: lead

    Esta parte de la documentación cubre las interfaces principales de Authcode.


.. _api.auth:

Objeto Auth
=============================================

*class* **Auth** (secret_key, db=None, **kwargs)

:Parámetros:
    secret_key:
        Llave secreta. Usada para generar el identificador de usuario o el token de recuperación de contraseña.

    db:
        Interfaz con la base de datos (SQLAlchemy). ``db.session`` debe ser la sesión se la base de datos y ``db.Model`` el modelo (declarativo) base.

    hash='pbkdf2_sha512':
        Nombre de la función de hashing a utilizar para guardar las contraseñas. Los valores posibles son ``pbkdf2_sha512``, ``pbkdf2_sha256``, ``sha512_crypt``, ``sha256_crypt`` o ``bcrypt``.

    rounds:
        Número de rondas a usar para la función de hashing. No cambies este valor a menos que tengas una razón poderosa para hacerlo.

    UserMixin:
        El *mixin* usado para crear el modelo de usuario final.

    RoleMixin:
        El *mixin* usado para crear el modelo de rol final.

    roles=False,:
        Crear un modelo de roles y métodos asociados. Si usas `RoleMixin` este valor se ignora.

    lazy_roles=True:
        Si es verdadero, los roles de un usuario no se cargan automáticamente (usando un JOIN) junto a la información del usuario sino solo cuando se necesiten.

    users_model_name='User':
        El nombre usado para el modelo de usuario.

    roles_model_name='Role':
        El nombre usado para el modelo de rol.

    user_name='user':
        Nombre que se usará para guardar el usuario actual en un objeto global. Por ejemplo, en Flask, se guardará en ``g.user``. Otros frameworks podrían guardarlo en el objeto request, por ejemplo.

    session_key='_uhmac':
        El nombre con que se guarda el identificador de usuario en la sesión.

    csrf_key='_csrf_token':
        El nombre del parámetro que contiene el código CSRF.

    csrf_header='X-CSRFToken':
        El nombre de la cabecera desde la cual leer el código CSRF al usar AJAX.
        Es la estándar, así que no deberías tener que cambiarla.

    redirect_key='next':
        El nombre del parámetro de la URL que guarda donde redirigir (por una única vez) luego de iniciar sesión exitosamente. Usado cuando se intenta ingresar a una página protegida y Authcode te muestra en cambio la página de inicio de sesión.

    sign_in_redirect='/':
        La URL a la cual Authcode redirige (a menos que se indique otra cosa en la vista) al iniciar la sesión.

    sign_out_redirect='/':
        La URL a la cual Authcode redirige al cerrar la sesión.

    url_sign_in='/sign-in/':
        La URL que se usará para la vista automática de inicio de sesión. Ignorada si “sign_in” no está en la lista de ``views``.

    url_sign_out='/sign-out/':
        La URL que se usará para la vista automática de cierre de sesión. Ignorada si “sign_out” no está en la lista de ``views``.

    url_reset_password='/reset-password/':
        La URL que se usará para la vista automática de recuperación de contraseña. Ignorada si “reset_password” no está en la lista de ``views``.

    url_change_password='/change-password/':
        La URL que se usará para la vista automática de cambio de contraseña. Ignorada si “change_password” no está en la lista de ``views``.

    views='sign_in sign_out reset_password change_password'.split(' '):
        Lista de vistas agregadas por Authcode automáticamente.

    views_prefix:
        Por defecto las vistas automáticas se crean con el nombre “auth_nombre”, por ejemplo: “auth_sign_in”. Este parámetro es un prefijo que puede agregarse a esos nombres, útil para cuando se usa más de un ``authcode.Auth`` en una misma aplicación.

    template_sign_in:
        Sobreescribe la plantilla para la página de iniciar sesión.

    template_sign_out=None:
        Sobreescribe la plantilla para la página mostrada al cerrar sesión. Si es ``None``, en vez de mostrar una página te redirige a ``auth.url_sign_out``.

    template_reset:
        Sobreescribe la plantilla para la página de recuperación de contraseña.

    template_reset_email:
        Sobreescribe la plantilla para el email de recuperación de contraseña.

    template_change_password:
        Sobreescribe la plantilla para la página de cambio de contraseña.

    reset_email_subject=u'Reset your password':
        El título del email de recuperación de una contraseña.

    case_insensitive=True:
        Convertir el login a minúsculas al crear al usuario y al autenticar.

    clear_session_on_logout=True:
        Borrar todos los datos guardados en la sesión al cerrarla, en vez de solo el identificador del usuario. La idea es prevenir un *ataque de persistencia de sesión*.

    password_minlen=5:
        Largo mínimo que debe tener una contraseña. Tratar de guardar una contraseña más corta fallará con una excepción ``ValueError``.

    password_maxlen=2048:
        Largo máximo que puede tener una contraseña.

        Esto existe para ayudar a a prevenir ataques de denegación de servicio mediante contraseñas muy largas. Lee https://www.djangoproject.com/weblog/2013/sep/15/security/ para un caso real.

        La autenticación con cualquier contraseña más larga que este valor fallará automáticamente.
        Tratar de guardar una contraseña más larga fallará con una excepción ``ValueError``.

    token_life=3*60:
        Minutos durante los cuales el enlace para recuperar una contraseña es válido.

    update_hash=True:
        Al iniciar sesión, si la función de hashing o el número de rondas ha cambiado, actualizar la contraseña guardada con esos nuevos parámetros.

    wsgi=wsgi.werkzeug:
        Módulo con la de interfaz para el *request* a usar. Los valores posibles son ``authcode.wsgi.werkzeug` y ``authcode.wsgi.bottle``.

    pepper=u'':
        Texto fijo que se agrega a todas las contraseñas antes de hashearlas. El problema es que cambiar este valor hace inválidas **todas** las contraseñas guardadas, y entonces no puedes cambiarlo aunque se haya filtrado.


Métodos
---------------------------------------------

set_hasher(hash, rounds=None):
    Reemplaza la función de hasheado por otra nueva, comprobando que este soportada por Authcode.

hash_password(secret):
    Toma la contraseña en texto plano y devuelve su hash. Si ``secret`` es ``None`` no la hashea si no que devuelve ``None``.

prepare_password(secret):
    Pre-procesa la contraseña antes de hashearla. En la práctica solo existe para que sobreescribas el método si lo necesitas.

password_is_valid(secret, hashed):
    Toma una contraseña en texto plano y un hash y comprueba si se trata o no de la misma contraseña

authenticate(credentials):
    Toma un diccionario con credenciales y llama, en orden, los backends de autenticación disponibles, hasta que alguno le devuelve un usuario. Authcode trae dos backends por defecto: ``auth.auth_password`` y ``auth.auth_token``.

    Si ninguno de los backends puede devolver un usuario, la función devuelve ``None``.

auth_password(credentials):
    Toma un diccionario del que trata de leer los valores ``login`` y ``password``. Si los encuentra, busca en la base de datos a un usuario con ese ``login`` y verifica que su contraseña sea la correcta.
    Si encuentra a un usuario y su contraseña coincide, devuelve a ese usuario, de lo contrario devuelve ``None``.
    Si la contraseña del usuario encontrado es ``None``, siempre devuelve ``None``, aunque la contraseña indicada en las credenciales también sea ``None``.

auth_token(credentials, token_life=None):
    Toma un diccionario del que trata de leer un valor ``token``; Este valor debe tener el formato generado por ``authcode.get_token`` (que a su vez puede ser invocado desde una instancia de usuario: ``usuario.get_token``).
    Si el token es válido devuelve al usuario que autentica, de lo contrario devuelve ``None``.

get_user(session=None):
    Lee el identificador de usuario desde la cookie de sesión (llave ``auth.session_key``), verifica que sea válido y devuelve al usuario correspondiente desde la base de datos.

login(user, remember=True, session=None):
    Guarda a ``user`` en la cookie se sesión. Si ``remember`` es verdadero, este valor seguirá ahí hasta que se llame a ``auth.logout``; De lo contrario, la sesión se borrará cuando el usuario cierre su navegador web.

    .. note::

        En vez de solo el id del usuario, lo que se guarda en la sesión es también un valor hasheado junto a la *sal* de la contraseña; De ese modo, un administrador o el usuario mismo, puede cerrar sesión en todas partes solamente cambiando (o re-guardando) su contraseña.

logout(session=None):
    Borra el identificador de usuario de la sesión. Si ``auth.clear_session_on_logout`` es verdadero (si por defecto), cualquier otra cosa guardada en la sesión también se borrará (la idea es prevenir un *ataque de persistencia de sesión*).

get_csrf_token(session=None):
    Obtiene de la sesión el token CSRF, o genera uno nuevo si no encuentra uno.

make_csrf_token():
    Genera un nuevo token CSRF.

csrf_token_is_valid(request, session=None):
    Verifica que el token CSRF enviado sea válido.

protected(*tests, **options):
    Decorador —o técnicamente una función que devuelve un decorador— usado para hacer que una vista sea solo accesible a usuarios logueados (o que además cumplan con otras condiciones).

    :Parametros:
        tests:
            Una o más funciones que tomen los argumentos de la vista y devuelvan ``True`` o ``False`. Todos los tests deben devolver verdadero para que la vista se muestre al usuario.

    :Opciones:
        role:
            Verifica que el usuario logueado tenga un rol con este nombre

        roles:
            Verifica que el usuario logueado tenga **cualquiera** de los roles en esta lista de nombres.

        csrf:
            Puede ser ``True``, ``False`` o ``None``.
            Si es ``None`` (el valor por defecto), el decorador revisará que haya un token CSRF válido para solicitudes del tipo POST, PUT o DELETE.
            Si ``True`` lo hará para todas las solicitudes sin importar su tipo.
            Si ``False``, el valor del token CSRF no será revisado.

        url_sign_in:
            Sobreescribe la URL de inicio de sesión por defecto para esta vista.
            Si alguna de las otras condiciones fallan (por ejemplo no hay un usuario logueado), Authcode te redirigirá ahí.
            Puede ser una URL o un ejecutable que devuelva la URL.


.. _api.setup_functions:

Funciones de setup
=============================================

*function* **setup_for_X** (auth, app=None, send_email=None, render=None, session=None, request=None)

:Parámetros:
    auth:
        Una instancia de la clase ``Auth``.

    app:
        La aplicación web. Ingóra este parámetro en frameworks en que no existe un objeto así.

    send_email:
        Función a la que Authcode llamará para enviar el email de recuperación de contraseña. Esta función deberá tomar como argumentos el usuario, el título del email y el cuerpo del mensaje.
        Ejemplo::

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

    render:
        Sobreescribe la función a la que Authcode llamará para generar el HTML de las vistas. La función de render debe tener esta firma:

            render(tmpl, **kwargs)

        donde ``tmpl`` es el nombre de la plantilla y ``kwargs`` los argumentos que se le pasan.

    session:
        Sobreescribe la referencia a la sesión.

    request:
        Sobreescribe la referencia a la solicitud de la página actual o a un ejecutable que la devuelva.


.. _api.setup_for_flask:

setup_for_flask
---------------------------------------------

- Agrega a ``flask.g.user`` una referencia (lazy) al usuario autenticado.

- Agrega ``csrf_token`` y ``auth`` a las variables globales de Jinja en ``app.jinja_env.globals``


.. _api.setup_for_bottle:

setup_for_bottle
---------------------------------------------

- Las sesiones deben estar activa. Por defecto la busca en ``bottle.request.session`` o la de Beaker.

- Cualquiera de los sistemas de plantillas soportados por Bottle funcionará, pero si no es Jinja2, tienes que proveer tus propias plantillas.

- Agrega a ``bottle.request.user`` una referencia (lazy) al usuario autenticado.
