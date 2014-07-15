


Tabla de usuarios
------------------------

Authcode no te fuerza a usar un nombre fijo o una estructura específica para la tabla de usuarios(1). En cambio, aprovecha el poder de SQLAlchemy y los *mixins* para dar la mayor flexibilidad sin sacrificar funcionalidad.

Funciona de esta forma: Authcode define una estructura mínima para la tabla de usuarios a la cual le agrega cualquier otro campo o método que tu definas en un mixin. De ese modo puedes extenderla sin tener que recurrir a una tabla separada de "perfil"(2).

.. figure:: _static/usermixin.png
   :width: 100 %

El detalle de las columnas mínimas que necesita Authcode que tenga la tabla de usuarios para funcionar puedes verlo en la sección `Detalles de los modelos por defecto`.

.. code:: python

    auth = Auth(config.SECRET_KEY, db=db, UserMixin=UserMixin,
                **config.AUTH_SETTINGS)

    User = auth.User


Tabla de roles
------------------------

Opcionalmente, Authcode también crea na tabla de "roles" y la conecta a la de los usuarios (puedes desactivar esto pasándo como parámetro `roles=False`). Un `rol` es simplemente un texto como "admin" que no hace nada de por sí pero puede servirte para asignar permisos diferentes a ciertos usuarios y no a otros. Puedes verlo también como un `grupo` de usuarios. Un usuario puede tener cero, uno o muchos roles según lo necesites.

Si se crea una tabla de roles, las instancias de usuario ganan automáticamente los métodos `has_role`, `add_role` y `remove_role`, para poder testear, asignar y quitar roles, respectívamente.

Puedes aumentar la tabla de roles de la misma forma que la tabla de usuarios: utilizando un mixin.

.. code:: python

    auth = Auth(config.SECRET_KEY, db=db, UserMixin=UserMixin,
                RoleMixin=RoleMixin, roles=True,
                **config.AUTH_SETTINGS)

    User = auth.User




(1) Como si o hace cierto conocido framework web que no quiero nombrar *cof cof Django*.
(2) Por supuesto, también puedes hacerlo si eso es lo que quieres.

