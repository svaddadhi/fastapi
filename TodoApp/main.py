import models
from database import engine
from routers import auth, todos

from fastapi import FastAPI

app = FastAPI()

models.Base.metadata.create_all(bind=engine)
app.include_router(auth.router)
app.include_router(todos.router)
