.. _advanced:

=============================================
Patrones avanzados
=============================================


Email en vez de login
=============================================


Agregar backends
=============================================

Las credenciales no tienen por que ser siempre el usuario y contraseña. De hecho, Authcode te permite manejar varios tipos de credenciales al mismo tiempo. Por ejemplo el mecanismo para restablecer de la contraseña aprovecha eso (autenticación con un código).

También puedes agregar tus propias métodos de autenticación, por ejemplo, este es el código necesario para que un usuario pueda usar su nombre de usuario **o** su email según prefiera:

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

Este ejemplo básicamente busca al usuario por su email y si lo encuentra, llama al método estándar de autenticación por login/password para que se encargue de validar la contraseña.


OAuth
=============================================

Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod
tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam,
quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo
consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse
cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non
proident, sunt in culpa qui officia deserunt mollit anim id est laborum.
