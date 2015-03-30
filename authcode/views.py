# coding=utf-8
from datetime import datetime

from ._compat import to_unicode


def pop_next_url(auth, request, session):
    next = session.pop(auth.redirect_key, None) or auth.sign_in_redirect or '/'
    if callable(next):
        next = next(request)
    if callable(getattr(session, 'save', None)):
        session.save()
    return next


def sign_in(auth, request, session, *args, **kwargs):
    if auth.get_user() and not auth.wsgi.is_post(request):
        next = pop_next_url(auth, request, session)
        return auth.wsgi.redirect(next)

    kwargs['error'] = None
    credentials = auth.wsgi.get_post_data(request) or {}

    if auth.wsgi.is_post(request) and auth.csrf_token_is_valid(request):
        if auth.session_key in session:
            del session[auth.session_key]

        user = auth.authenticate(credentials)
        if user and not user.deleted:
            user.last_sign_in = datetime.utcnow()
            remember = bool(credentials.get('remember', True))
            auth.login(user, remember=remember)
            auth.db.session.commit()

            next = pop_next_url(auth, request, session)
            return auth.wsgi.redirect(next)

        kwargs['error'] = True

    kwargs['auth'] = auth
    kwargs['credentials'] = credentials
    kwargs['csrf_token'] = auth.get_csrf_token
    resp = auth.render_template('sign_in', **kwargs)
    return auth.wsgi.make_response(resp)


def sign_out(auth, request, *args, **kwargs):
    # the logout action itself must be CSRF protected,
    # but the view could be called twice by mistake
    # so we ignore the second one instead of raising an error
    if auth.csrf_token_is_valid(request):
        auth.logout()

    if auth.template_sign_out:
        kwargs['auth'] = auth
        resp = auth.render_template('sign_out', **kwargs)
        return auth.wsgi.make_response(resp)

    next = auth.sign_out_redirect or '/'
    if callable(next):
        next = next(request)
    return auth.wsgi.redirect(next)


def reset_password(auth, request, token=None, *args, **kwargs):
    credentials = auth.wsgi.get_post_data(request) or {}
    kwargs['ok'] = False
    kwargs['error'] = False
    kwargs['token'] = token

    if not token and auth.get_user():
        return auth.wsgi.redirect(auth.url_change_password)

    if token:
        user = auth.authenticate({'token': token})
        if user:
            auth.login(user)
            return change_password(auth, request, manual=False, **kwargs)
        kwargs['error'] = 'WRONG TOKEN'

    elif auth.wsgi.is_post(request) and auth.csrf_token_is_valid(request):
        login = auth.wsgi.get_from_params(request, 'login') or ''
        user = auth.User.by_login(login)
        if user:
            reset_url = auth.wsgi.make_full_url(
                request,
                auth.url_reset_password + user.get_token() + '/'
            )
            data = {
                'user': user,
                'login': user.login,
                'reset_url': reset_url,
                'site_name': auth.wsgi.get_site_name(request),
                'expire_after': auth.token_life,
            }
            _email_token(auth, user, data)
            kwargs['ok'] = True
        else:
            kwargs['error'] = 'WRONG USER'

    kwargs['auth'] = auth
    kwargs['credentials'] = credentials
    kwargs['csrf_token'] = auth.get_csrf_token
    resp = auth.render_template('reset', **kwargs)
    return auth.wsgi.make_response(resp)


def _email_token(auth, user, data):
    msg = to_unicode(
        auth.render_template('reset_email', **data)
    )
    auth.send_email(
        user,
        auth.reset_email_subject or u'Reset your password',
        msg
    )


def change_password(auth, request, manual=True, *args, **kwargs):
    user = auth.get_user()
    if not user:
        return auth.wsgi.redirect(auth.url_sign_in)

    kwargs['ok'] = False
    kwargs['error'] = None

    if auth.wsgi.is_post(request):
        if not auth.csrf_token_is_valid(request):
            return auth.wsgi.raise_forbidden()

        password = auth.wsgi.get_from_params(request, 'password') or ''
        np1 = auth.wsgi.get_from_params(request, 'np1') or ''
        np2 = auth.wsgi.get_from_params(request, 'np2') or ''
        len_np1 = len(np1)

        if len_np1 < auth.password_minlen:
            kwargs['error'] = 'TOO SHORT'

        elif len_np1 > auth.password_maxlen:
            kwargs['error'] = 'TOO LONG'

        elif (not np2) or (np1 != np2):
            kwargs['error'] = 'MISMATCH'

        elif manual and not user.has_password(password):
            kwargs['error'] = 'FAIL'

        else:
            user.password = np1
            auth.db.session.commit()
            auth.login(user)
            kwargs['ok'] = True

    kwargs['auth'] = auth
    kwargs['manual'] = manual
    kwargs['csrf_token'] = auth.get_csrf_token
    resp = auth.render_template('change_password', **kwargs)
    return auth.wsgi.make_response(resp)
