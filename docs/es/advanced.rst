.. _advanced:

=============================================
Patrones avanzados
=============================================


Email en vez de login
=============================================



Agregar backends de autenticación
=============================================

Las credenciales no tienen por que ser siempre el usuario y contraseña. De hecho, Authcode te permite manejar varios tipos de credenciales al mismo tiempo.

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


OAuth
=============================================

OAuth
