import os, configparser


config = configparser.ConfigParser()
config.read("../../" + os.environ['CONFIG_FILE'])

#config for github SSO
CLIENT_ID = config.get("GITHUB", "Client_id")
CLIENT_SECRET = config.get("GITHUB", "Client_Secret")
redirect_url = config.get("GITHUB", "Redirect_uri")

#config for jwt generation
SECRET_KEY = config.get("JWT", "Secret_key")
ALGORITHM = config.get("JWT", "Algorithm") 
ACCESS_TOKEN_EXPIRE_MINUTES = int(config.get("JWT", "Access_token_expire_minutes"))

bucket = config.get("INFLUX", "Bucket")
org = config.get("INFLUX", "Org")
token = config.get("INFLUX", "Token")
influx_url = config.get("INFLUX", "url")

mongo_url = config.get("MONGO", "url")
port = int(config.get("MONGO", "port"))
username = config.get("MONGO", "username")
password = config.get("MONGO", "password")
