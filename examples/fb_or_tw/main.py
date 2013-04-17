# -*- coding: utf-8 -*-
from flask import g, render_template

from app import app, db
from auth.models import auth, User


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/user/')
@auth.protected()
def profile():
    return render_template('profile.html')


if __name__ == '__main__':
    db.create_all()
    app.run(debug=True)
