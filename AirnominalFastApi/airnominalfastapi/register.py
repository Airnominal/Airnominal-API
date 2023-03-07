import random
import string
from pydantic import BaseModel
from typing import List
import secrets

from fastapi import Depends, HTTPException, APIRouter
from fastapi.security import HTTPAuthorizationCredentials
from auth import security, has_access_and_get_user
import uuid
from mongo import stations
router = APIRouter()

class RegisterSensor(BaseModel):
    sensor_name: str
    quantity: str
    unit: str

class RegisterStation(BaseModel):
    station_name: str
    sensors: List[RegisterSensor]


def generate_strings():
    used_strings = set()
    while True:
        new_string = ''.join(random.choices(string.ascii_uppercase + string.digits, k=3))
        if new_string not in used_strings and not new_string in ["END", "LAT", "LON"]:
            used_strings.add(new_string)
            yield new_string

def generate_password():
    alphabet = string.ascii_lowercase + string.digits
    password = ''.join(secrets.choice(alphabet) for i in range(6))
    return password

@router.post("/register")
async def register(register: RegisterStation, credentials: HTTPAuthorizationCredentials= Depends(security)):
    gen = generate_strings()
    user = has_access_and_get_user(credentials)

    reg = dict(register)
    reg["station_id"] = str(uuid.uuid4())
    reg["token"] = generate_password()
    reg["lon"] = None
    reg["lat"] = None
    reg["updated"] = None
    for i, element in enumerate(reg["sensors"]):
        reg["sensors"][i] = dict(element)
        reg["sensors"][i]["sensor_id"] = str(uuid.uuid4())
        reg["sensors"][i]["short_id"] = next(gen)
    reg["owner_id"] = user["id"]
    reg["owner_name"] = user["display_name"]
    
    stations.insert_one(reg)
    rtn = reg.copy()
    rtn["_id"] = str(rtn["_id"])
    return rtn

@router.get("/my_stations")
async def get_my_stations(credentials: HTTPAuthorizationCredentials= Depends(security)):
    user = has_access_and_get_user(credentials)
    print(stations.find({"owner_id" : user["id"]}))
    return [station for station in stations.find({"owner_id" : user["id"]}, {'_id': 0})]

class DeleteStation(BaseModel):
    id: str
@router.post("/delete_station")
async def delete_station(item: DeleteStation, credentials: HTTPAuthorizationCredentials= Depends(security)):
    user = has_access_and_get_user(credentials)
    station = stations.delete_one({"station_id": item.id, "owner_id": user["id"]})
    return True
    