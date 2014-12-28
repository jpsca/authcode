.. _authorization:

=============================================
Autorización
=============================================

.. container:: lead

    Si fueras a crear un sistema para tu blog, tendrías páginas públicas pero no quisieras que cualquiera pudiera editar o borrar posts en él. Necesitas un mecanismo para que a ciertas páginas solo tengan acceso usuarios autenticados, quizas que también cumplan con algunas condiciones. De eso se trata esta guía.


Protegiendo tus vistas: *auth.protected*
=============================================

Hay ciertas vistas a las que solo tiene sentido que tengan acceso los usuarios autenticados. Authcode te hace fácil lograrlo por medio del decorador ``auth.protected()``. Ejemplo:

.. code-block:: python

    @auth.protected()
    def myview():
        return u'Solo puede verme un usuario autenticado'

.. note::

    Nota que el decorador está siendo llamado (tiene un par de paréntesis al final de la línea). Estos son necesarios, si los olvidas tendrás un error. [#]_

.. warning:: ¡Cuidado!
    Si defines las rutas a tus vistas con decoradores —como lo hace Flask— ten mucho cuidado en poner el decorador de autenticación **después** del de la ruta o, de otro modo, tus vistas quedarán desprotegidas. Hazlo de esta forma:

   .. code-block:: python

        @app.route('/admin/')
        @auth.protected()
        def myview():
            ...


Roles
---------------------------------------------

Una necesidad muy común es darle acceso al usuario solo si tiene un rol o permiso específico. Por lo mismo, Authcode tiene una forma directa de hacerlo: usando el argumento

    ``role = nombredelrol``

Para darle acceso a más de un rol, puedes usar

    ``roles = [nombredelrol1, nombredelrol2,  ...]``

(nota que, en este caso, el argumento se llama ``roles``, en plural)

Ejemplo:

.. code-block:: python

    @auth.protected(role='admin')
    def myview1():
        return u'Solo puede verme los usuarios con el rol “admin”'

    @auth.protected(roles=['foo', 'bar'])
        def myview2():
            return u'Solo puede verme los usuario con el rol “foo”, el rol “bar” (o ambos)'

Pruebas
---------------------------------------------

El decorador también puede tomar como argumento una o más funciones para “probar” al usuario. Las pruebas toman como argumentos al usuario autenticado y cualquier otro argumento que la vista haya recibido. Solo si todas devuelven `True` se da acceso a la vista al usuario.

.. code-block:: python

    def test_can_delete(user, *args, **kwargs):
        return user.has_role('admin') or user.can_delete == True

    @auth.protected(test_can_delete)
    @app.route('/admin/')
    def myview1():
        ...


Finalmente, el último truco del decorador ``@auth.protected`` es el poder activar/desactivar la protección contra ataques CSRF, como podrás leerlo en la siguiente sección.


Protección CSRF
=============================================

Esta biblioteca incluye un mecanismo para protegerte de ataques **CSRF** (*Cross Site Request Forgery*). Este tipo de ataque ocurre cuando un sitio web malicioso contiene un enlace, un formulario o código JavaScript que busca realizar alguna acción en tu sitio web, aprovechando las credenciales de un usuario ya autenticado.

Funciona por que es el navegador del usuario quien hace la solicitud y, aunque esta se origina en un sitio diferente al atacado, todas las solicitudes a él incluyen la *cookie* que identifica al usuario.

Un ataque relacionado, llamado *login CSRF* —en que el sitio atacante engaña al navegador del usuario para que se autentique con las credenciales de alguien más— también esta cubierto.

La primera linea de defensa es asegurarte que ninguno de los ``GET`` en tus sitios tengan efectos secundarios. Las solicitudes por métodos ``POST``, ``PUT``, ``DELETE``, etc. puedes entonces protegerlas siguiendo los pasos de abajo.


Como usarla
---------------------------------------------

Authcode genera un código único para cada sesión de cada usuario que este debe usar al hacer cualquier actividad en el sitio. Nadie más puede ver ese código: el de otros usuarios es diferente. Exigiéndolo para cualquier acción que haga cambios, te aseguras que solo funcionen las páginas generadas por tu sitio y no los de otro sitio web malicioso.

1. En todos los formularios enviado por ``POST``, usa ``csrf_token()`` para incluir este código como un campo oculto. e.g.:

.. code-block:: html+jinja
   :emphasize-lines: 2

    <form action="" method="post">
      <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
      ...
      <button type="submit">Guardar</button>
    </form>

Esto **no** debes hacerlo en los formularios que se envían a URLs externas, o estarás divulgando el codigo a ese otro sito, lo que puede ocasionar una vulnerabilidad.

2. Si la vista correspondiente está decorada con ``@auth.protected`` y el formulario **no** es enviado por ``GET`` o ``HEAD``, no tienes que hacer nada, pues el decorador ya está validando el código CSFR  automáticamente.

Puedes forzar a que se haga la validación con otros métodos de envio, por ejemplo ``GET``, agregando el parámetro ``csrf=True`` al decorador.

.. code-block:: python

    @auth.protected(csrf=True)
    def myview():
        ...

Asi mismo, si lo necesias, puedes desactivar la revisión automática usando el parámetro ``csrf=False``. Luego, el método :meth:`~authcode.Auth.csrf_token_is_valid` te servirá para hacer la validación manual cuando lo necesites.

.. code-block:: python

    @auth.protected(csrf=False)
    def myview():
        ...
        if not auth.csrf_token_is_valid(request):
            raise Forbidden()
        ...

AJAX
+++++++++++++++++++++++++++++++++++

Para usar la protección contra ataques CSRF en solicitudes AJAX, podrías pasar el código manualmente en cada solicitud que hagas, pero hay una mejor forma.

Authcode acepta recibir el código CSRF como valor de la cabecera HTTP “X-CSRFToken”. Esto es conveniente, por que las bibliotecas de JavaScript más populares permiten incluir automáticamente cabeceras personalizadas en todas las solicitudes  AJAX.

El siguiente ejemplo usa la biblioteca jQuery para mostrar como funciona; Solo es necesario ejecutar la función ``ajaxSetup`` una vez, para que todas las  solicitudes AJAX incluyan el código CSRF automáticamente.

En este caso, he insertado el código CSRF en una etiqueta ``<meta>`` en cada página:

.. code-block:: html+jinja

    <meta name="csrf_token" content="{{ csrf_token() }}">

y de ahí puede leerlo el código para poner la cabecera en las solicitudes AJAX, ademas de impedir que el código CSRF se envie a otros dominios, usando `settings.crossDomain <http://api.jquery.com/jQuery.ajax>`_ en jQuery 1.5.1 y más nuevos:

.. code-block:: javascript

    // Obtengo el código CSRF de mi etiqueta <meta>
    window.CSRFToken = $('meta[name="csrf_token"]').attr('content');

    function csrfSafeMethod(method) {
        // Estos métodos HTTP no necesitan protección CSRF
        return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
    }
    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            if (!csrfSafeMethod(settings.type) && !this.crossDomain) {
                xhr.setRequestHeader("X-CSRFToken", window.CSRFToken);
            }
        }
    });


Autorización denegada
=============================================

Si un usuario no autenticado intenta acceder una de las vistas protegidad por ``@auth.protected()``, es redirigido por a la página de login por defecto, definida en las opciones globales. Esto pagina puede cambiar para una vista específica usando el parámetro ``url_sign_in``, que puede ser una URL fija o un invocable que devuelva la URL que quieres.

La URL que el usuario intentaba visitar queda guardada en su sesión y una vez que se autentica, se le redirige ahí.

Hay casos, sin embargo, que un usuario autenticado no tendrá permisos para acceder a una vista, si no tiene cierto rol o no pasa cierta prueba, o si se requería un código CSRF y este no se encuentra o es inválido. En esos caso, el decorador ``@auth.protected()`` lanza una excepción ``403 Forbidden``.

No suele haber una página por defecto para este error, o si la hay no es muy amigable, por lo que vas a querer usar tu propia vista. Los detalles de como hacerlo varían en cada framework, pero por ejemplo en Flask puedes agragarla de este modo:

.. code-block:: python

    @app.errorhandler(403)
    def gone(error=None):
        return render_template('forbidden.html'), 403


.. [#] Técnicamente es una función que al ejecutarse devuelve un decorador.
