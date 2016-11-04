from scrypt import hash as shash
from base64 import b85encode
from os import urandom


def gen_salt(length=16):
    salt = b85encode(urandom(length))
    return salt.decode()


def hash_password(password, salt):
    hashed = b85encode(shash(password, salt))
    return hashed.decode()
