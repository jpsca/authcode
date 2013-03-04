# -*- coding: utf-8 -*-
from datetime import datetime


def sign_in(auth, request, session, **kwargs):
    next = session.get(auth.redirect_key) or auth.sign_in_redirect or '/'
    if callable(next):
        next = next(request)

    if auth.session_key in session:
        session.pop(auth.redirect_key, None)
        return auth.wsgi.redirect(next)
    
    kwargs['error'] = None
    credentials = auth.wsgi.get_post_data(request) or {}
    
    if auth.wsgi.is_post(request):
        user = auth.authenticate(credentials)
        if user:
            if hasattr(user, 'last_sign_in'):
                user.last_sign_in = datetime.utcnow()
                auth.db.commit()
            auth.login(user)
            session.pop(auth.redirect_key, None)
            return auth.wsgi.redirect(next)
        
        kwargs['error'] = True
    
    kwargs['auth'] = auth
    kwargs['credentials'] = credentials
    return auth.render(auth.template_sign_in, **kwargs)


def sign_out(auth, request, **kwargs):
    auth.logout()
    if auth.template_sign_out:
        return auth.render(auth.template_sign_out, **kwargs)

    next = auth.sign_out_redirect or '/'
    if callable(next):
        next = next(request)
    return auth.wsgi.redirect(next)


def reset_password(auth, request, token=None, **kwargs):
    credentials = auth.wsgi.get_post_data(request) or {}
    kwargs['ok'] = False
    kwargs['error'] = None

    if not token and auth.get_user():
        return auth.wsgi.redirect(auth.url_change_password)
    
    if token:
        user = auth.authenticate({'token': token})
        if user:
            auth.login(user)
            return change_password(auth, request, manual=False, **kwargs)
        kwargs['error'] = 'WRONG TOKEN'
    
    elif auth.wsgi.is_post(request):
        login = auth.wsgi.get_from_params(request, 'login') or ''
        user = auth.User.by_login(login)
        if not user:
            kwargs['error'] = 'NOT FOUND'
        else:
            reset_url = auth.wsgi.make_full_url(request, 
                auth.url_reset_password + user.get_token() + '/')
            data = {
                'login': user.login,
                'reset_url': reset_url,
                'site_name': auth.wsgi.get_site_name(request),
                'expire_after': auth.token_life,
            }
            _email_token(auth, user, data)
            kwargs['ok'] = True

    kwargs['auth'] = auth
    kwargs['credentials'] = credentials
    return auth.render(auth.template_reset, **kwargs)


def _email_token(auth, user, data):
    msg = unicode(auth.render(auth.template_reset_email, **data))
    auth.send_email(user, 'Reset your password', msg)


def change_password(auth, request, manual=True, **kwargs):
    user = auth.get_user()
    if not user:
        return auth.wsgi.redirect(auth.url_sign_in)

    kwargs['ok'] = False
    kwargs['error'] = None
    
    if auth.wsgi.is_post(request):
        csrf_token = auth._get_csrf_token_from_request(request)
        if not auth.csrf_token_is_valid(csrf_token):
            return auth.wsgi.raise_forbidden()

        password = auth.wsgi.get_from_params(request, 'password') or ''
        np1 = auth.wsgi.get_from_params(request, 'np1') or ''
        np2 = auth.wsgi.get_from_params(request, 'np2') or ''
        
        # Validate the new password
        if len(np1) < auth.password_minlen:
            kwargs['error'] = 'TOO SHORT'
        
        elif (not np2) or (np1 != np2):
            kwargs['error'] = 'MISMATCH'
        
        elif manual and not user.has_password(password):
            kwargs['error'] = 'FAIL'
        
        else:
            user.password = np1
            auth.db.commit()
            auth.login(user)
            kwargs['ok'] = True
    
    kwargs['auth'] = auth
    kwargs['manual'] = manual
    kwargs['csrf_token'] = auth.get_csrf_token
    return auth.render(auth.template_change_password, **kwargs)

