
Authcode example: Signing in using Twitter or Facebook
=======================================================


This is an example on how you use AuthCode when the signing in is made via OAuth instead of the standard login/password views.

For the OAuth part I'm using the flask_oauth library, but the principles are the same for any other OAuth library you might use.


How to run locally
------------------

1. Create a virtualenv to contain the required python libraries (eg: `virtualenv env`) and activate it (eg: `source env/bin/activate`).

2. Install the required python libraries by doing
    
    pip install -r requirements-dev.txt

3. Open the ``settings.py`` file.

    a) Go to:
       https://dev.twitter.com/apps
       Make a new application and paste in the settings the key and the secret.

    b) Repeat for Facebook going here:
       https://developers.facebook.com/apps
       Make a new application and paste in the settings the key and the secret.

4. Run the server with: `python main.py`


Notes
------

The ``os.getenv(…)`` stuff is for deploying on Heroku.


