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

::

    from shake import NotAllowed
    from shake_auth import protected, invalid_csrf
    
    @protected(csrf=False)
    def myview(request):
        if invalid_csrf(request):
            raise NotAllowed()
        ...


AJAX
```````````

To use the CSRF protection with AJAX calls, AuthCode accept the CSRF token in the custom HTTP header X-CSRFToken, for ease of use with popular JavaScript toolkits which allow insertion of custom headers into all AJAX requests.

The following example using the jQuery toolkit demonstrates this; the call to jQuery’s ajaxSetup will cause all AJAX requests to send back the CSRF token in the custom X-CSRFTOKEN header:

    $(document).ajaxSend(function(event, xhr, settings) {
        function getCookie(name) {
            var cookieValue = null;
            if (document.cookie && document.cookie != '') {
                var cookies = document.cookie.split(';');
                for (var i = 0; i < cookies.length; i++) {
                    var cookie = jQuery.trim(cookies[i]);
                    // Does this cookie string begin with the name we want?
                    if (cookie.substring(0, name.length + 1) == (name + '=')) {
                        cookieValue = decodeURIComponent(cookie.substring(name.length + 1));
                        break;
                    }
                }
            }
            return cookieValue;
        }
        function sameOrigin(url) {
            // url could be relative or scheme relative or absolute
            var host = document.location.host; // host + port
            var protocol = document.location.protocol;
            var sr_origin = '//' + host;
            var origin = protocol + sr_origin;
            // Allow absolute or scheme relative URLs to same origin
            return (url == origin || url.slice(0, origin.length + 1) == origin + '/') ||
                (url == sr_origin || url.slice(0, sr_origin.length + 1) == sr_origin + '/') ||
                // or any other URL that isn't scheme relative or absolute i.e relative.
                !(/^(\/\/|http:|https:).*/.test(url));
        }
        function safeMethod(method) {
            return (/^(GET|HEAD|OPTIONS|TRACE)$/.test(method));
        }

        if (!safeMethod(settings.type) && sameOrigin(settings.url)) {
            xhr.setRequestHeader("X-CSRFToken", getCookie('csrftoken'));
        }
    });

Alternatively, you could also insert the token in your HTML template, as a JavaScript variable, and read it later from your script, e.g.::

    <script>var CSRF_TOKEN = '{{ csrf_token() }}';</script>

and later, in your javascript code::

    $.post(‘/theurl’, {
        … your data …
       '_csrf': CSRF_TOKEN
    });




