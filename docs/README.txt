

class UserMixin(object):
    name = db.Column(db.Unicode)
    surname = db.Column(db.Unicode, default=u'')
    email = db.Column(db.Unicode, default=u'')
    birthday = db.Column(db.Date, nullable=True)

    @property
    def fullname(self):
        return u'{} {}'.format(self.name, self.surname).strip()


auth = Auth(config.SECRET_KEY, db=db, UserMixin=UserMixin,
            **config.AUTH_SETTINGS)

User = auth.User

----------------------------------------------------------------------

class User(object):

    id = Column(Integer, primary_key=True)
    login = Column(Unicode, nullable=False, unique=True)
    _password = Column(String(255), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    modified_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_sign_in = Column(DateTime, nullable=True)
    deleted = Column(Boolean, default=False)

    @classmethod
        def by_login(cls, login):
            ...


----------------------------------------------------------------------

class User(object):

    id = Column(Integer, primary_key=True)
    login = Column(Unicode, nullable=False, unique=True)
    _password = Column(String(255), nullable=True)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    modified_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    last_sign_in = Column(DateTime, nullable=True)
    deleted = Column(Boolean, default=False)

    name = db.Column(db.Unicode)
    surname = db.Column(db.Unicode, default=u'')
    email = db.Column(db.Unicode, default=u'')
    birthday = db.Column(db.Date, nullable=True)

    @property
    def fullname(self):
        return u'{} {}'.format(self.name, self.surname).strip()

    @classmethod
        def by_login(cls, login):
            ...
