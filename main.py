from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
import secrets

app = FastAPI()

def get_current_username(credentials: HTTPBasicCredentials = Depends(security)):
    current_username_bytes = credentials.username.encode("utf8")
    correct_username_bytes = b"stanleyjobson"
    is_correct_username = secrets.compare_digest(
        current_username_bytes, correct_username_bytes
    )
    current_password_bytes = credentials.password.encode("utf8")
    correct_password_bytes = b"swordfish"
    is_correct_password = secrets.compare_digest(
        current_password_bytes, correct_password_bytes
    )
    if not (is_correct_username and is_correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username

class Ikeike(BaseModel):
    name: str
    height: float
    appearance: int
    money: int


@app.get("/ikeike/")
def no_name_error():
    return HTTPException(status_code=400, detail="prease access '/ikeike/{name}'")

@app.get("/users/me")
def read_current_user(username: str = Depends(get_current_username)):
    return {"username": username}

@app.get("/ikeike/{name}")
def become_ikeike(name: str, num: int=0):
    return name + " is イケイケ" + "!"*num

@app.post("/ikeike/", status_code=200)
async def create_ikeike(shobo: Ikeike):
    shobo.height += 15
    shobo.appearance *= 4700
    shobo.money *= 55000 

    return shobo
