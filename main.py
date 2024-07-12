from fastapi import FastAPI,Depends,HTTPException,status
from sqlalchemy.orm import Session
import schemas
from database import get_db
import crud
import security
import models


app = FastAPI()



@app.post("/create_user", response_model=schemas.User)
def create_user(user: schemas.UserCreate,session: Session = Depends(get_db)):
    user.password = security.get_password_hash(user.password)
    return  crud.create_user(db=session,user=user)

@app.get("/user/{user_id}", response_model=schemas.User)
def saludo(user_id:int,session: Session = Depends(get_db)):
    return crud.get_user(db=session,user_id=user_id)

@app.post("/login", response_model=schemas.User)
def login(user: schemas.UserBase,session: Session = Depends(get_db)):

    user_db = session.query(models.User).filter(models.User.email==user.email).first()
    if not user_db:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND,detail=f"Usuario con el email {user.email} no encontrado")

    if not security.verify_password(user.password,user_db.password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,detail=f"Contraseña o email incorrecta")

    return user_db
