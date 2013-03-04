## Updating the hashes
When the technology change the hardware gets faster, you'll want to update the hash algorithm you are deciding to use now. However, the whole point of store hashes is to make impossible to recover the original password, so you can't simply re-hash the passwords, because you don't know them.
Authorizer is prepared to deal with that scenario. You just define a new supported hasher in the settings and, when the user logs in again, her password hash will be automatically updated to new format and stored.

You can turn this behaviour off by setting the `update_hash` parameter to `False`.

Right now the library supports changing between the three valid hashers: "bcrypt", "pbkdf2_sha512" and "sha512_crypt", but also to read hashes in these formats: "django_salted_sha1", "django_salted_md5", "django_des_crypt", "hex_sha512", "hex_sha256", "hex_sha1", "hex_md5". Click on them for more information.

## Dealing with unsupported hash formats

