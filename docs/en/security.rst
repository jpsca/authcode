.._security:

============================
Security
============================

..container :: lead

    This section expands some basic concepts this library deals with.


.._security.about_passwords:

Managing passwords
=============================================

Passwords do not only protect your site but, because people often reuse them in several sites, can be also the door to other systems, otherwise secure.

..pull-quote ::

    The first rule of password handling is **never** store passwords.

Instead, all you keep is a *password hash*. To verify a password given by a user, you calculate the hash of that and compare it with the one you have stored.

..pull-quote ::

    The second rule of password handling is that you don't use just any hashing function.

First, hashing functions should not generate the same hash for different passwords (they has to be "resistant to collisions"), or someone could access your account with a password different from yours.

Second, many of the most popular functions such as MD5, SHA1, etc. are very fast and efficient; which is perfect for what we were invented, but it's the last thing you want when hashing passwords.

When an attacker has obtained a copy of your database, and given that you cannot get the original password from the hash, what remains is to test one by one, the hashes of all combinations of numbers, letters and symbols. It is what is called a *brute force attack*.

Sounds like an impossibly long process, but when you use a hashing function that can process thousands of passwords per second, is a matter of hours, even minutes in some cases!

..pull-quote ::

    A hash function for passwords must be *designed to be slow*.

The three hashing functions that you can use with Authcode (``bcrypt``, ``sha_crypt`` and ``pbkdf2``) are designed not only to be slow, but also to delay the process further by calculating the final hash in many rounds, re-hashing the previous result over and over again. ``sha_crypt`` for example, by default do this 100'000 times.

For ordinary users, this means a delay of a fraction of a second, but for an attacker can be the difference between hours and months.

.. note::

    Design a hashing algorithm is not something anyone can or should do. These three algorithms have been reviewed and tested at depth by experts from around the world for at least ten years.


Salt
---------------------------------------------

Even if it takes time and resources, you might pre-calculate a table of hashes for all combinations of letters, numbers and symbols until x characters. Once completed, would be very fast compare hashes of users with the table, finding all passwords that long or shorter.

The way to counteract this attack is simply to add to the password a group of letters, numbers and symbols randomly to make it much longer.

The salt is generated randomly *for each password change*. And it's not a secret, its role is solely to prevent the lookup tables to work. You also need to have it to verify passwords, so the guards in "plain text" with the final hash.

..figure :: _static / salt.png
   : Align: center

Add salt is added that although two passwords are the same, the two hashes will always be different advantage.


Pepper (or "global salt")
---------------------------------------------

..warning ::

    The main problem is that change does pepper invalid ** ** all saved passwords, and then you can not change it even if it was filtered.

    Just in case, uses no Authcode unless you are the passes as ``pepper``, parameter


Another type of attack, orders of magnitude faster than brute force, is a dictionary attack * *. It's basically a list of words to try combinations of them- -and commonly used passwords. "12345678", "PizzaPizza" or even variations in safe appearance as "p4 $$ word" and "123456789j" are lost cases against this attack.

Like salt, the "Pepper" is a text that is added to the password before hashearla: your "123456" with a pepper "loremipsum 'becomes` `loremipsum123456``. Sure to be useful, pepper has to be much longer: ** beam that is at least 32 characters **.

Unlike salt, this value is (1) unique for all hashes of the system, (2) secret, (3) defined by you, and (4) is not saved with the original hash, but in your own source code.

..figure :: _static / pepper.png
   : Align: center

Although a copy of the database is taken, the theory is that * no * Access to the source code, even a brute force becomes unfeasible * almost * [#] _.


.._security.response:

Report a security issue
=============================================

..container :: lead

    We appreciate your concern.

Maintaining the security of authentication library is critical that potentially affects all who use it. Your opinions and comments thereon are always welcome.

If the problem you want to report urgent or sensitive (can cause an attacker has access to the data of another user or may supplant) send directly to security@lucumalabs.com. Use `our public key <http://lucumalabs.com/lucumalabs-security.pub>` _ to keep your secure message [#] _ and please give us a safe way to respond. We will respond just as we can, usually within 24 hours.

For other problems, please create a report https://github.com/jpscaletti/Authcode/issues.



..rubric :: Footnotes

..[#] But remember this: http://xkcd.com/538/

..[#] Using PGP. You can read how this site: https://ssd.eff.org/es/module/como-usar-pgp-para-windows-pc (there are also instructions for Mac and Linux)