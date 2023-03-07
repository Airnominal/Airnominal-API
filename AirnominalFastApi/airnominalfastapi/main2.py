#engine = create_engine('druid://admin:RRj35SAsQv6abNBp@druid.gimvic.eu:8082/druid/v2/sql/')
from datetime import datetime, timedelta
import datetime
import os
import uvicorn
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi_sso.sso.github import GithubSSO
from fastapi.security import OAuth2PasswordBearer

from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel
import random

import influxdb_client
from influxdb_client.client.write_api import SYNCHRONOUS



#config for github SSO
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
CLIENT_ID = "5cc2edd581cadd5a10d5"
CLIENT_SECRET = "a0c9cbd7cec444b9fb8f3b16b3cd98d813f2bcf4"

#config for jwt generation
SECRET_KEY = "09d25e094faa6ca2556c818166b7a9563b93f7099f6f0f4caa6cf63b88e8d3e7"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

#config for influx-db
bucket = "Airnominal-data2"
org = "Airnominal"
token = "DFUh1vGGeC2UHrAY8UW-t_3ylXa5LLo7mID-vaZ8UFgaggNjqRpz_lxmNErbazdJQA7q_F8stomdWK_YVHaE1A=="
url = "http://192.168.64.10:8086"

client = influxdb_client.InfluxDBClient(
    url=url,
    token=token,
    org=org
)

def random_date_time():
    today = datetime.datetime.now()
    one_month_ago = today - datetime.timedelta(days=30)
    seconds_between = (today - one_month_ago).total_seconds()
    random_seconds = random.randint(0, int(seconds_between))
    random_date_time = one_month_ago + datetime.timedelta(seconds=random_seconds)
    return random_date_time.isoformat()

# Write script
write_api = client.write_api(write_options=SYNCHRONOUS)

for i in range(100):
    p = influxdb_client.Point("data").from_dict(
        
            {
                "measurement": "data",
                "tags": {
                    "owner_id": "1235989238",
                    "owner_name": "Alenka Mozer",
                    "station_id": "3894838983",
                    "station_name": "test station",
                    "sensor_id": "878754375",
                    "sensor_name": "CO2-01",
                    "display_quantity": "CO2 (ppm)",
                    "quantity": "CO2",
                    "unit": "ppm"
                },
                "time": random_date_time(),
                "fields": {
                    "lat": random.uniform(-180, 180),
                    "lon": random.uniform(-90, 90),
                    "value": random.uniform(0, 30)
                }
            }
        
    )
    write_api.write(bucket=bucket, org=org, record=p)

for i in range(100):
    p = influxdb_client.Point("data").from_dict({
                "measurement": "data",
                "tags": {
                    "owner_id": "12478273847",
                    "owner_name": "Alenka Gojzar",
                    "station_id": "738475983475",
                    "station_name": "not-test station",
                    "sensor_id": "2354532",
                    "sensor_name": "CO2-02",
                    "display_quantity": "CO2 (ppm)",
                    "quantity": "CO2",
                    "unit": "ppm"
                },
                "time": random_date_time(),
                "fields": {
                    "lat": random.uniform(-180, 180),
                    "lon": random.uniform(-90, 90),
                    "value": random.uniform(0, 30)
                }
            })
    write_api.write(bucket=bucket, org=org, record=p)

for i in range(100):
    p = influxdb_client.Point("data").from_dict({
                "measurement": "data",
                "tags": {
                    "owner_id": "12478273847",
                    "owner_name": "Alenka Gojzar",
                    "station_id": "738475983475",
                    "station_name": "not-test station",
                    "sensor_id": "2354534",
                    "sensor_name": "CO2-03",
                    "quantity": "CO2",
                    "display_quantity": "CO2 (ppm)",
                    "unit": "ppm"
                },
                "time": random_date_time(),
                "fields": {
                    "lat": random.uniform(-180, 180),
                    "lon": random.uniform(-90, 90),
                    "value": random.uniform(0, 30)
                }
            })
    write_api.write(bucket=bucket, org=org, record=p)

for i in range(100):
    p = influxdb_client.Point("data").from_dict(
        
            {
                "measurement": "data",
                "tags": {
                    "owner_id": "1235989238",
                    "owner_name": "Alenka Mozer",
                    "station_id": "3894838983",
                    "station_name": "test station",
                    "sensor_id": "874654532",
                    "sensor_name": "SO2-02",
                    "display_quantity": "SO2 (ppb)",
                    "quantity": "SO2",
                    "unit": "ppb"
                },
                "time": random_date_time(),
                "fields": {
                    "lat": random.uniform(-180, 180),
                    "lon": random.uniform(-90, 90),
                    "value": random.uniform(0, 30)
                }
            }
        
    )
    write_api.write(bucket=bucket, org=org, record=p)
write_api.write(bucket=bucket, org=org, record=p)
write_api.close()

app = FastAPI()

sso = GithubSSO(
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    redirect_uri="http://localhost:8000/auth/callback",
    allow_insecure_http=True,
)

security = HTTPBearer()

@app.get("/")
async def hello():
    return {"hello": "world"}

@app.get("/auth/login")
async def auth_init():
    """Initialize auth and redirect"""
    return await sso.get_login_redirect()


@app.get("/auth/callback")
async def auth_callback(request: Request):
    """Verify login"""
    user = await sso.verify_and_process(request)
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data=dict(user), expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer"}
    return user



def create_access_token(data: dict, expires_delta: timedelta | None = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt




def has_access_and_get_user(credentials: HTTPAuthorizationCredentials):
    """
        Function that is used to validate the token in the case that it requires it
    """
    token = credentials.credentials

    try:
        payload = jwt.decode(token, key='secret', options={"verify_signature": False,
                                                           "verify_aud": False,
                                                           "verify_iss": False})
        return payload
    except JOSEError as e:  # catches any exception
        raise HTTPException(
            status_code=401,
            detail=str(e))

@app.get("/hello")
async def hello(credentials: HTTPAuthorizationCredentials= Depends(security)):
    data = has_access_and_get_user(credentials)
    return "Hello " + data["display_name"]
