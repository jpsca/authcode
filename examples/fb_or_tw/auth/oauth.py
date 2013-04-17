# -*- coding: utf-8 -*-
from flask import session
from flask_oauth import OAuth

import settings

oauth = OAuth()


twitter = oauth.remote_app('twitter',
    base_url='https://api.twitter.com/1/',
    request_token_url='https://api.twitter.com/oauth/request_token',
    access_token_url='https://api.twitter.com/oauth/access_token',
    authorize_url='https://api.twitter.com/oauth/authorize',
    consumer_key=settings.TWITTER_KEY,
    consumer_secret=settings.TWITTER_SECRET
)


facebook = oauth.remote_app('facebook',
    base_url='https://graph.facebook.com/',
    request_token_url=None,
    access_token_url='/oauth/access_token',
    authorize_url='https://www.facebook.com/dialog/oauth',
    consumer_key=settings.FACEBOOK_APP_ID,
    consumer_secret=settings.FACEBOOK_APP_SECRET,
    request_token_params={'scope': 'email'}
)


@twitter.tokengetter
def get_twitter_token(token=None):
    return session.get('twitter_token')



