from typing import Annotated
from fastapi import FastAPI,Depends,HTTPException,status
from fastapi.security import OAuth2PasswordBearer,OAuth2PasswordRequestForm
from sqlalchemy.orm import Session
import schemas
from database import get_db
import crud
import security
import models
from jwt import ExpiredSignatureError


app = FastAPI()


oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")


def get_user_online(token: str = Depends(oauth2_scheme),session: Session = Depends(get_db)) -> models.User:
    try:
        payload = security.decode_token(token)
        user_id = payload.get("sub")
    except ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail="Token expirado")
    return crud.get_user(db=session,user_id=user_id)

@app.post("/create_user", response_model=schemas.User)
def create_user(user: schemas.UserCreate,session: Session = Depends(get_db)):
    user.password = security.get_password_hash(user.password)
    return  crud.create_user(db=session,user=user)

@app.get("/get_current_user", response_model=schemas.User)
def get_current_user(user: models.User = Depends(get_user_online)):

    return user

@app.post("/login", response_model=security.Token)
def login(user: schemas.UserBase,session: Session = Depends(get_db)):

    user_db = session.query(models.User).filter(models.User.email==user.email).first()
    if not user_db:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail=f"Usuario con el email {user.email} no encontrado")

    if not security.verify_password(user.password,user_db.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail=f"Contraseña o email incorrecta")
    token = security.create_access_token(data={"sub":user_db.id},expires_delta=60)

    return  security.Token(access_token=token,token_type="bearer")

@app.post("/token")
async def login_for_access_token(
    form_data: Annotated[OAuth2PasswordRequestForm, Depends()],session: Session = Depends(get_db)
) -> security.Token:
    user_db = session.query(models.User).filter(models.User.username==form_data.username).first()
    if not user_db:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail=f"Usuario con el username {form_data.username} no encontrado")

    if not security.verify_password(form_data.password,user_db.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail=f"Contraseña o email incorrecta")

    token = security.create_access_token(data={"sub":user_db.id},expires_delta=60)

    return  security.Token(access_token=token,token_type="bearer")

@app.patch("/update_email")
def update_email(email: str, user: models.User = Depends(get_user_online), session: Session = Depends(get_db)):
    user.email = email
    session.commit()
    session.refresh(user)
    return user