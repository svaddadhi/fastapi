import models
from database import engine
from routers import admin, auth, todos, users

from fastapi import FastAPI

app = FastAPI()

models.Base.metadata.create_all(bind=engine)
app.include_router(auth.router)
app.include_router(todos.router)
app.include_router(admin.router)
app.include_router(users.router)
