# coding=utf-8
import functools
import logging
from uuid import uuid4

from ._compat import to_unicode


class AuthorizationMixin(object):

    # Useful for setting a cookie only if the CSRF token has changed.
    csrf_token_has_changed = False

    def get_csrf_token(self, session=None):
        logger = logging.getLogger(__name__)
        if session is None:
            session = self.session
        csrf_token = session.get(self.csrf_key)
        if not csrf_token:
            logger.debug(u'New CSFR token')
            csrf_token = self.make_csrf_token()
            session[self.csrf_key] = csrf_token
            if callable(getattr(session, 'save', None)):
                session.save()
        return csrf_token

    def make_csrf_token(self):
        self.csrf_token_has_changed = True
        return str(uuid4()).replace('-', '')

    def protected(self, *tests, **kwargs):
        """Factory of decorators for limit the access to views.

        :tests: *function, optional
            One or more functions that takes the args and kwargs of the
            view and returns either `True` or `False`.
            All test must return True to show the view.

        Options:

        :role: str, optional
            Test for the user having a role with this name.

        :roles: list, optional
            Test for the user having **any** role in this list of names.

        :csrf: bool, None, optional
            If ``None`` (the default), the decorator will check the value
            of the CSFR token for POST, PUT or DELETE requests.
            If ``True`` it will do the same also for all requests.
            If ``False``, the value of the CSFR token will not be checked.

        :url_sign_in: str, function, optional
            If any required condition fail, redirect to this place.
            Override the default URL. This can also be a callable.

        :request: obj, optional
            Overwrite the request for testing.

        The rest of the ``key=value`` pairs in ``kwargs`` are interpreted as tests.
        The user must have a property `key` with a value equals to `value`.
        If the user has a method named `key`, that method is called with
        `value` as a single argument and must return True to show the view.

        """
        _role = kwargs.pop('role', None)
        _roles = kwargs.pop('roles', None) or []
        _csrf = kwargs.pop('csrf', None)
        _url_sign_in = kwargs.pop('url_sign_in', None)
        _request = kwargs.pop('request', None)

        if _role:
            _roles.append(_role)
        _roles = [to_unicode(r) for r in _roles]

        _tests = tests
        _user_tests = kwargs

        def decorator(f):
            @functools.wraps(f)
            def wrapper(*args, **kwargs):
                logger = logging.getLogger(__name__)
                request = _request or self.request or args and args[0]
                url_sign_in = self._get_url_sign_in(request, _url_sign_in)

                user = self.get_user()
                if not user:
                    return self._login_required(request, url_sign_in)

                if hasattr(user, 'has_role') and _roles:
                    if not user.has_role(*_roles):
                        logger.debug(u'User `{0}`: has_role fail'.format(user.login))
                        logger.debug(u'User roles: {0}'.format([r.name for r in user.roles]))
                        return self.wsgi.raise_forbidden()

                for test in _tests:
                    test_pass = test(user, *args, **kwargs)
                    if not test_pass:
                        logger.debug(u'User `{0}`: test fail'.format(user.login))
                        return self.wsgi.raise_forbidden()

                for name, value in _user_tests.items():
                    user_test = getattr(user, name)
                    test_pass = user_test(value, *args, **kwargs)
                    if not test_pass:
                        logger.debug(u'User `{0}`: test fail'.format(user.login))
                        return self.wsgi.raise_forbidden()

                disable_csrf = _csrf == False  # noqa
                if (not self.wsgi.is_idempotent(request) and not disable_csrf) or _csrf:
                    if not self.csrf_token_is_valid(request):
                        logger.debug(u'User `{0}`: invalid CSFR token'.format(user.login))
                        return self.wsgi.raise_forbidden("CSFR token isn't valid")

                return f(*args, **kwargs)
            return wrapper
        return decorator

    def replace_flask_route(self, bp, *args, **kwargs):
        """Replace the Flask `app.route` or `blueprint.route` with a version
        that first apply the protected decorator to the view, so all views
        are automatically protected."""
        protected = self.protected

        def protected_route(rule, **options):
            """Like :meth:`Flask.route` but for a blueprint.  The endpoint for the
            :func:`url_for` function is prefixed with the name of the blueprint.
            """
            def decorator(f):
                endpoint = options.pop("endpoint", f.__name__)
                protected_f = protected(*args, **kwargs)(f)
                bp.add_url_rule(rule, endpoint, protected_f, **options)
                return f
            return decorator

        bp.route = protected_route

    def csrf_token_is_valid(self, request, session=None):
        token = self._get_csrf_token_from_request(request)
        return token and self._csrf_token_is_valid(token, session)

    def _csrf_token_is_valid(self, token, session=None):
        new_token = self.get_csrf_token(session=session)
        return new_token == token

    def _login_required(self, request, url_sign_in):
        self.session[self.redirect_key] = self.wsgi.get_full_path(request)
        if callable(getattr(self.session, 'save', None)):
            self.session.save()
        return self.wsgi.redirect(url_sign_in)

    def _get_url_sign_in(self, request, url_sign_in):
        url_sign_in = url_sign_in or self.url_sign_in
        if callable(url_sign_in):
            url_sign_in = url_sign_in(request)
        return url_sign_in or '/'

    def _get_csrf_token_from_request(self, request):
        token = self.wsgi.get_from_params(request, self.csrf_key) or \
            self.wsgi.get_from_headers(request, self.csrf_header)
        return token
