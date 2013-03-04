
```python
db = SQLAlchemy()
auth = authcode.Auth(SECRET_KEY, db=db, **kwargs)

class User(auth.User):
    pass

app = Flask('test')
authcode.setup_for_flask(auth, app)
```
