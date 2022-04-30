import uuid
import os
from cryptography.fernet import Fernet
import yaml


def read_yaml(file_path):
    with open(file_path, 'r') as f:
        return yaml.load(f, Loader=yaml.SafeLoader)

def get_value(file_name, key):
    file_path = os.path.join(os.getcwd(), file_name)
    data = read_yaml(file_path)
    for k in key.split("."):
        data = data[k]
    return data

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

    if len(passwd) < 8 or len(passwd) > 20:
        return 'Length should be between 8-20', False
          
    if not any(char.isdigit() for char in passwd):
        return 'Password should have at least one number', False
          
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
