import uuid
import os
import hashlib
from cryptography.fernet import Fernet

def create_id():
    return uuid.uuid1().hex

def encrypt(password:str):
    key = Fernet.generate_key()
    f = Fernet(key)
    return f.encrypt(password.encode()).hex()+"$"+key.hex()

def decrypt(cypher:str):
    password, key = map(lambda x: bytes.fromhex(x), cypher.split('$'))
    f = Fernet(key)
    return f.decrypt(password).decode()

def password_check(passwd):     
    SpecialSym =['$', '@', '#']

    if len(passwd) < 8:
        return 'Length should be at least 6', False
          
    if not any(char.isdigit() for char in passwd):
        return 'Password should have at least one numeral', False
          
    if not any(char.isupper() for char in passwd):
        return 'Password should have at least one uppercase letter', False
          
    if not any(char.islower() for char in passwd):
        return 'Password should have at least one lowercase letter', False
          
    if not any(char in SpecialSym for char in passwd):
        return 'Password should have at least one of the symbols $@#', False

    return 'done', True


# if __name__ == "__main__":
#     msg = "hello"
#     cipher = encrypt(msg)
#     print(cipher)
#     print(decrypt(cipher))
