------------------------
Autenticación
------------------------

Authcode separa la *autenticación* del *login*. La parte de autenticación recibe unas credenciales —como un nombre de usuario y una contraseña— y regresa a la instancia del usuario identificado. El login recibe a una instancia de usuario y guarda en la sesión un un código para identificarlo en adelante (hasta que se haga logout).

¿Por qué separarlos? Por que así puede autenticarse a un usuario por otros medios, como via OAuth por Twitter o Facebook, pero sin perder el resto de la funcionalidad que Authcode te da.


Credenciales
------------------------

Las credenciales no tienen por que ser siempre el usuario y contraseña. De hecho, Authcode te permite manejar varios tipos de credenciales al mismo tiempo. Por ejemplo el mecanismo de reseteo de la contraseña aprovecha esa ventaja (autenticación con un código).

También puedes agregar tus propias métodos de autenticación, por ejemplo, este es el código necesario para que un usuario pueda usar su nombre de usuario **o** su email según prefiera:

.. code:: python

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
