# -*- coding: utf-8 -*-
import os

from flask import g, render_template, redirect, url_for

from app import app, db
from auth.models import auth, User


@app.route('/')
def index():
    if g.user:
        return redirect(url_for('profile'))
    return render_template('index.html')


@app.route('/user/')
@auth.protected()
def profile():
    return render_template('profile.html')


if __name__ == '__main__':
    db.create_all() # just for this demo

    port = int(os.getenv("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

