# coding=utf-8
from datetime import datetime

from flask import g, flash, request, redirect, url_for, session
from flask_oauth import OAuth

from app import app, db
import settings

from .models import auth, User, get_unique_login


oauth = OAuth()


twitter = oauth.remote_app(
    'twitter',
    base_url='https://api.twitter.com/1/',
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorize_url='https://api.twitter.com/oauth/authorize',
    consumer_key=settings.TWITTER_KEY,
    consumer_secret=settings.TWITTER_SECRET
)


facebook = oauth.remote_app(
    'facebook',
    base_url='https://graph.facebook.com/',
    request_token_url=None,
    access_token_url='/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    consumer_key=settings.FACEBOOK_APP_ID,
    consumer_secret=settings.FACEBOOK_APP_SECRET,
    request_token_params={'scope': 'email'}
)


@app.route('/sign-in/twitter/')
def twitter_login():
    next = request.args.get('next') or url_for('profile')
    if 'twitter_token' in session:
        del session['twitter_token']
    return twitter.authorize(
        callback=url_for('twitter_authorized', next=next)
    )


@app.route('/sign-in/twitter/authorized/')
@twitter.authorized_handler
def twitter_authorized(resp):
    if resp is None:
        flash(u'You denied the request to sign in.')
        return redirect(url_for('sign_in'))

    session['twitter_token'] = resp['oauth_token']

    # >>> resp
    # {
    #     "oauth_token_secret": "...",
    #     "oauth_token": "...",
    #     "user_id": "11640332",
    #     "screen_name": "jpscaletti"
    # }
    user = db.query(User).filter(User.twitter_id == resp['user_id']).first()

    # user never signed on
    if not user:
        if g.user:
            user = g.user
        else:
            login = get_unique_login(resp['screen_name'])
            user = User(login=login)
            db.add(user)
        user.twitter_id = resp['user_id']

    user.last_sign_in = datetime.utcnow()
    # in any case we update the authentication token in the db
    # In case the user temporarily revoked access we will have
    # new tokens here.
    user.twitter_username = resp['screen_name']
    user.twitter_token = resp['oauth_token']
    user.twitter_secret = resp['oauth_token_secret']
    # don't forget to commit **before** doing ``auth.login(user)`
    db.commit()

    auth.login(user)
    next = request.args.get('next') or url_for('profile')
    return redirect(next)


@twitter.tokengetter
def get_twitter_token(token=None):
    return session.get('twitter_token')


@app.route('/sign-in/facebook/')
def facebook_login():
    next = request.args.get('next') or None
    if 'facebook_token' in session:
        del session['facebook_token']
    return facebook.authorize(
        callback=url_for('facebook_authorized', next=next, _external=True)
    )


@app.route('/sign-in/facebook/authorized/')
@facebook.authorized_handler
def facebook_authorized(resp):
    if resp is None:
        flash(u'Access denied: reason=%s error=%s' % (
            request.args['error_reason'],
            request.args['error_description'])
        )
        return redirect(url_for('sign_in'))

    session['facebook_token'] = (resp['access_token'], '')
    me = facebook.get('/me')

    # >>> me.data
    # {
    #     "username": "jpscaletti",
    #     "id": "581604320",
    #     "email": "juanpablo@lucumalabs.com"
    #     "locale": "en_US",
    #     "timezone": -5,
    #     "first_name": "Juan-Pablo",
    #     "last_name": "Scaletti",
    #     "name": "Juan-Pablo Scaletti",
    #     "gender": "male",
    #     "link": "http://www.facebook.com/jpscaletti",
    #     "updated_time": "2013-04-15T06:33:55+0000",
    # }

    user = db.query(User).filter(User.facebook_id == me.data['id']).first()

    # user never signed on
    if user is None:
        if g.user:
            user = g.user
        else:
            login = get_unique_login(me.data.get('username'))
            user = User(login=login)
            db.add(user)
        user.facebook_id = me.data['id']

    user.last_sign_in = datetime.utcnow()
    # in any case we update the authentication token in the db
    # In case the user temporarily revoked access we will have
    # new tokens here.
    user.facebook_token = resp['access_token']
    # don't forget to commit **before** doing ``auth.login(user)`
    db.commit()

    auth.login(user)
    next = request.args.get('next') or url_for('profile')
    return redirect(next)


@facebook.tokengetter
def get_facebook_oauth_token():
    return session.get('facebook_token')
