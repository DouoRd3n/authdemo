import hmac
import hashlib
import base64
import json
from typing import Optional
from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response

app = FastAPI()

SECRET_KEY = '8f650c7107a90721440bf6177e0d2422384518d29c75a808392ce8d6eb27c709'
PASSWORD_SALT = '0bcf2ee548385ca3016ffc8db2dcd2e16bec0ef4f99a09834c2621dc336e3395'

users = {
    "alexey@user.com":{
        "name" : "Олексій",
        "password" : "bf2bbeb725b3b3732395915c7d7c938aa0c6706ac422b558372269e051291ec2",
        "balance" : 100_000
    }, 
    "petr@user.com":{
        "name" : "Петро",
        "password" : "78df5f46860b9ca9c367bfc931dbd67635153e76c8a2e8b154d3ef92f71c2d7f",
        "balance" : 555_555
    }
}
def verify_password(password: str, username: str) -> bool:
    pasword_hash = hashlib.sha256((password + PASSWORD_SALT).encode()) \
        .hexdigest().lower() 
    stored_password_hash = users[username]['password']
    return  pasword_hash == stored_password_hash
       
def get_username_from_signet_string(username_signed: str) -> Optional[str]:
    username_base64, sign = username_signed.split(".")
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sind_data(username)
    if hmac.compare_digest(valid_sign, sign):
        return username

def sind_data(data: str) -> str:
    """Повертаєми підписані данні data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()


@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)) :
    with open('templates/login.html', 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")
    
    valid_username = get_username_from_signet_string(username)
    if not valid_username:
        resrponse = Response(login_page, media_type="text/html")
        resrponse.delete_cookie(key="username")
        return resrponse
    
    try:
        user = users[valid_username]
    except KeyError:
        resrponse = Response(login_page, media_type="text/html")
        resrponse.delete_cookie(key="username")
        return resrponse
    
    return Response(f"Привіт, {users[valid_username]['name']}!<br />"
                    f"Баланс: {users[valid_username]['balance']}", 
                    media_type="text/html")
    

@app.post("/login")
def procces_login_page(username : str = Form(...), password : str = Form(...)):

    user = users.get(username)
    
    if not user or not verify_password(password, username):
        return Response(
            json.dumps({
                "success": False,
                "message": "я вас не знаю!"
            }),
            media_type="application/json") 
    
    responce =  Response(
        json.dumps({
                "success": True,
                "message": f"Привіт, {user['name'] }!<br /> Баланс: {user['balance']}"
            }),
        media_type="application/json")
    username_signed = base64.b64encode(username.encode()).decode() + "." + \
        sind_data(username)
    responce.set_cookie(key = "username", value=username_signed)

    return responce