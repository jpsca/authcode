Cross Site Request Forgery (CSRF) protection
----------------------------------------------

This extension provides an easy-to-use protection against [Cross Site
Request Forgeries][http://en.wikipedia.org/wiki/Cross-site_request_forgery].
This type of attack occurs when a malicious web site creates a link or form button that is intended to perform some action on your Web site, using the credentials of a logged-in user who is tricked into clicking on the link in their browser.


How to Use
```````````

1.  In any view that uses a POST form, use the CSFR global variable inside the <form> element
    URL, e.g.::

        <form action="" method="post">
            …
            
            <input type="hidden" name="_csrf_token" value="{{ csrf_token() }}">
            
            <button type="submit">Save</button>
        </form>

    This should *not* be done for forms that target external URLs, since that would cause the CSRF token to be leaked, leading to a vulnerability.

2.  If the corresponding view function is decorated with `@auth.protected()` the CSFR token will be automatically checked. If no CSFR token is found or its value is incorrect, the decorator will raise a ``NotAllowed`` HTTP exception.

    For those cases when you need to check the CSFR token for all
    request methods (eg. GET), pass the parameter `csrf=True` to the decorator.

    If you are using the decorator but prefer to do the check manually, you can disable this feature by passing a `csrf=False parameter to the decorator.


Manual checking
```````````````

To manually validate the CSRF token use the :meth:`~authcode.Auth.csrf_token_is_valid` method.

.. code-block:: python

    @protected(csrf=False)
    def myview(request):
        if auth.csrf_token_is_valid(request):
            raise Forbidden()
        ...


AJAX
```````````

To use the CSRF protection with AJAX calls, AuthCode accept the CSRF token in the custom HTTP header X-CSRFToken, for ease of use with popular JavaScript toolkits which allow insertion of custom headers into all AJAX requests.

The following example using the jQuery library demonstrates this; the call to jQuery’s ajaxSetup will cause all AJAX requests to send back the CSRF token in the custom X-CSRFTOKEN header.

In this case, the value of the CSRF token is on a `<meta>` tag on every page.

    <meta name="csrf_token" content="{{ csrf_token() }}">

.. code-block:: javascript

    window.CSRFToken = $('meta[name="csrf_token"]').attr('content');
  
    $.ajaxSetup({
        beforeSend: function(xhr, settings) {
            var url = settings.url.replace(location.origin, '');
            var isAbsoluteUrl = /^[a-z0-9]+:\/\/.*/.test(url);
            // Only send the token to relative URLs i.e. locally.
            if (! isAbsoluteUrl) {
                xhr.setRequestHeader("X-CSRFToken", window.CSRFToken);
            }
        }
    });

An alternative is to insert the token as a JavaScript variable, and read it later from your script, e.g.::

    <script>var CSRF_TOKEN = '{{ csrf_token() }}';</script>

and later, in your javascript code::

    $.post(‘/theurl’, {
        … your data …
       '_csrf_token': CSRF_TOKEN
    });




