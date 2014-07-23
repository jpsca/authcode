.. _authentication:

=============================================
Autenticación
=============================================


Integración con tus modelos
=============================================

No tiene sentido una biblioteca de autenticación que no se integre con tu modelo de usuarios. El problema es que motras bibliotecas en el pasado te han obligado a usar su modelo de usuarios, con su estructura y sin que le puedas agregar nuevos campos [1]_ o ni siquiera definir el nombre de la tabla. Creo que eso es pedir demasiado.

Authcode en cambio, aprovecha el poder de SQLAlchemy y los *mixins* para dar la mayor flexibilidad sin sacrificar funcionalidad.

Funciona de esta forma: parte de una estructura mínima predefinida para el modelo de usuarios y le agrega cualquier otro campo o método que tu definas en un mixin. Y puedes llamar la tabla como quieras, si tu mixin incluye un ``__tablename__`` (si no, por defecto es ``users``).

De ese modo puedes extenderla sin tener que recurrir a una tabla separada de “perfil” [2]_.

.. code-block:: python

    class UserMixin(object):
        name = db.Column(db.Unicode)
        surname = db.Column(db.Unicode, default=u'')
        email = db.Column(db.Unicode, default=u'')
        birthday = db.Column(db.Date, nullable=True)

        @property
        def fullname(self):
            return u'{} {}'.format(self.name, self.surname).strip()

    auth = Auth(SECRET_KEY, db=db, UserMixin=UserMixin, **AUTH_SETTINGS)
    User = auth.User  # Modelo de Usuario

lo que se traduce a:

.. figure:: _static/usermixin.png
   :width: 100 %

El modelo combinado está en ``auth.User``, para que lo conectes con el resto de tus modelos.

.. note::

    Hay unos cuantos campos que Authcode necesita que tenga la tabla de usuarios para funcionar.
    Estas vienen por defecto en el modelo, así que no es necesario que las agregues en tu mixin.

    .. code-block:: python

        class AuthUserMixin(object):

            id = Column(Integer, primary_key=True)
            login = Column(Unicode, nullable=False, unique=True)
            password = Column(String(255), nullable=True)
            last_sign_in = Column(DateTime, nullable=True)
            deleted = Column(Boolean, default=False)

    :``login``: Puede ser un nombre de usuario o un email.
    :``password``: Automáticamente *hashea* cualquier valor que se le asigne.
        Más abajo hay detalles de este proceso.
    :``las_sign_in``: Es la fecha de la última autenticación.
        La vista de autenticación por defecto se encarga de actualizarla.
        Es necesaria para poder invalidar los enlaces de recuperación de contraseña
        (antes de que pase su tiempo de expiración) entrando con tus credenciales
        actuales.
    :deleted: Un simple booleano para activar o desactivar la cuenta.
        Puedes ignorarlo si no lo necesitas.


Roles
---------------------------------------------

Opcionalmente, Authcode también puede crear un modelo de “roles” y conectarlo al de los usuarios. Un ``rol`` es simplemente un texto como “admin”, puedes verlo también como un `grupo` de usuarios. Un usuario puede tener uno, muchos o ningún rol según lo necesites.

No tiene ningún efecto de por sí, pero puede servirte para activar o desactivar funcionalidades en tu sitio deacuerdo a que roles el usuario autenticado tiene.

Hay dos formas de activar los roles; Una es inicializando Authcode con el argumento ``roles=True``:

.. code-block:: python

    auth = Auth(SECRET_KEY, db=db, UserMixin=UserMixin, roles=True,
                **AUTH_SETTINGS)

    User = auth.User  # Modelo de Usuario
    Role = auth.Role  # Modelo de Rol

la otra es pasarle un *mixin* para la tabla de roles:

.. code-block:: python

    auth = Auth(SECRET_KEY, db=db, UserMixin=UserMixin, RoleMixin=RoleMixin,
                **AUTH_SETTINGS)

    User = auth.User  # Modelo de Usuario
    Role = auth.Role  # Modelo de Rol

Este mixin es muy similar al de la tabla de usuarios. Por defecto un rol tiene solo un campo —su nombre. Utilizando este mixin puedes agregarle los campos extra que quieras (como una descripción, por ejemplo). El modelo final de roles está en ``auth.Role``.

Cuando los roles están activados, las instancias de usuarios tienen estos tres nuevos métodos:

* ``user.add_role(name)``:
    Le agrega el rol con nombre ``name`` a este usuario.
    Si el rol no existe previamente, se crea automáticamente.
    Devuelve la misma instancia de usuario

* ``user.remove_role(name)``:
    Le quita el rol con nombre ``name`` a este usuario.
    Funciona sin problemas aunque el usuario no tenga ese rol o el que rol no exista.

* ``user.has_role(*names)``:
    Evalua si el usuario tiene al menos uno de los roles listados.
    Ejemplo:

    .. code-block:: python

        user.add_role('foo')
        assert user.has_role('bar', 'foo', 'admin')  # True
        assert user.has_role('foo')  # True
        assert user.has_role('bar', 'admin')  # False


Manejo de las contraseñas
=============================================


Proceso de login
=============================================

Authcode separa la *autenticación* del *login*. La parte de autenticación recibe unas credenciales —como un nombre de usuario y una contraseña— y regresa a la instancia del usuario identificado. El login recibe a una instancia de usuario y guarda en la sesión un un código para identificarlo en adelante (hasta que se haga logout).

¿Por qué separarlos? Por que así puede autenticarse a un usuario por otros medios, como via OAuth por Twitter o Facebook, pero sin perder el resto de la funcionalidad que Authcode te da.


Vistas de autenticación
=============================================


Recuperar contraseña
=============================================

Lorem ipsum dolor sit amet, consectetur adipisicing elit, sed do eiusmod
tempor incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam,
quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo
consequat. Duis aute irure dolor in reprehenderit in voluptate velit esse
cillum dolore eu fugiat nulla pariatur. Excepteur sint occaecat cupidatat non
proident, sunt in culpa qui officia deserunt mollit anim id est laborum.


.. [1] *cof cof Django*.
.. [2] Por supuesto, también puedes crear un modelo de perfil si quieres. Authcode no se quejará.
