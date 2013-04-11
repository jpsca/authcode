


Permission: a unique string representing an action, usually a verb. Like "delete", "edit", etc.







AuthCode separates *authentication* from *login*. Authentication validates some credentials, like a username and a password, and return a user instance. Login takes a user istance and make it logged in teh session.
Why separate these two? Because sometimes you want to authenticate  the user by other means (like by Twitter via OAuth) but still use the rest of the Authcode library to manage what can or cannot do.


Authentication
---------------




Access control
---------------

