import uuid
import os
from cryptography.fernet import Fernet
import yaml
from urllib.parse import quote

def read_mysql_env():
    try:
        host = quote(os.getenv("MYSQL_HOST"))
        user = quote(os.getenv("MYSQL_USER"))
        password = quote(os.getenv("MYSQL_PASSWORD"))
        
        if (user == "" or user is None) or (password == "" or password is None):
            return None
        return host, user, password
    
    except Exception as e:
        print(e)
        return None

def read_mysql_config():
    host = quote(get_value('config.yaml', 'MYSQL_HOST'))
    user = quote(get_value('config.yaml', 'MYSQL_USER'))
    password = quote(get_value('config.yaml', 'MYSQL_PASSWORD'))
    if (user == "" or user is None) or (password == "" or password is None):
        return None
    return host, user, password

def get_mysql_url():
    output = read_mysql_env()
    if output is None:
        output = read_mysql_config()
    if output is None:
        return None
    host, user, password = output
    print("Mysql: ", output)
    if host == "":
        host = "localhost"
    return f'mysql://{user}:{password}@{host}/password_saver'

def read_mail_env():
    try:
        server = os.getenv("MAIL_SERVER", "")
        username = os.getenv("MAIL_USERNAME", "")
        password = os.getenv("MAIL_PASSWORD", "")
        port = int(os.getenv("MAIL_PORT", "465"))
        use_tls = True if os.getenv("MAIL_USE_TLS") == "True" else False
        use_ssl = True if os.getenv("MAIL_USE_SSL") == "True" else False

        if (server == "" or server is None) or (username == "" or username is None) or (password == "" or password is None):
            return None
        return server, username, password, port, use_tls, use_ssl
    except Exception as e:
        print(e)
        return None

def read_mail_config():
    server = get_value('config.yaml', 'MAIL_SERVER')
    username = get_value('config.yaml', 'MAIL_USERNAME')
    password = get_value('config.yaml', 'MAIL_PASSWORD')
    port = get_value('config.yaml', 'MAIL_PORT')
    use_tls = get_value('config.yaml', 'MAIL_USE_TLS')
    use_ssl = get_value('config.yaml', 'MAIL_USE_SSL')

    if server == "" or username == "" or password == "":
        raise Exception("MAIL_SERVER, MAIL_USERNAME, MAIL_PASSWORD is empty")
    return server, username, password, port, use_tls, use_ssl

def get_mail():
    output = read_mail_env()
    if output is None:
        output = read_mail_config()
    print("Mail: ", output)
    return output

def read_admin_env():
    try:
        username = os.getenv("ADMIN_EMAIL")
        password = os.getenv("ADMIN_PASSWORD")

        if (username == "" or username is None) or (password == "" or password is None):
            return None
        return username, password
    except Exception as e:
        print(e)
        return None

def read_admin_config():
    username = get_value('config.yaml', 'ADMIN_EMAIL')
    password = get_value('config.yaml', 'ADMIN_PASSWORD')

    if username == "" or password == "":
        raise Exception("ADMIN_EMAIL, ADMIN_PASSWORD is empty")
    return username, password

def get_admin():
    output = read_admin_env()
    if output is None:
        output = read_admin_config()
    print("Admin: ", output)
    return output

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
