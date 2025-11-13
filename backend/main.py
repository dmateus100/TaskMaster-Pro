from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
import datetime
import secrets
import hashlib

app = FastAPI(title="Gestor de Tareas Avanzado", version="2.0.0")

# Configuración CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Modelos de datos
class UserBase(BaseModel):
    email: str
    name: str

class UserCreate(UserBase):
    password: str

class User(UserBase):
    id: int

class LoginRequest(BaseModel):
    email: str
    password: str

class TaskBase(BaseModel):
    title: str
    description: Optional[str] = None
    priority: str = "media"
    status: str = "pendiente"

class TaskCreate(TaskBase):
    pass

class Task(TaskBase):
    id: int
    user_id: int
    created_at: str
    updated_at: str

# Base de datos en memoria
users_db = {}
tasks_db = []
current_user_id = 1
current_task_id = 1

# Función para hash de contraseñas
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

# Función para verificar usuario
def verify_user(email: str, password: str) -> Optional[User]:
    user_data = users_db.get(email)
    if user_data and user_data["password_hash"] == hash_password(password):
        return User(id=user_data["id"], email=email, name=user_data["name"])
    return None

# Endpoints de Autenticación
@app.post("/register")
async def register(user_data: UserCreate):
    """Registrar nuevo usuario"""
    if user_data.email in users_db:
        raise HTTPException(status_code=400, detail="El usuario ya existe")
    
    global current_user_id
    users_db[user_data.email] = {
        "id": current_user_id,
        "name": user_data.name,
        "password_hash": hash_password(user_data.password)
    }
    
    current_user_id += 1
    return {"message": "Usuario registrado exitosamente", "user_id": current_user_id - 1}

@app.post("/login")
async def login(login_data: LoginRequest):
    """Iniciar sesión"""
    user = verify_user(login_data.email, login_data.password)
    if not user:
        raise HTTPException(status_code=401, detail="Credenciales inválidas")
    
    # Crear token simple (en producción usar JWT)
    token = secrets.token_hex(32)
    users_db[login_data.email]["token"] = token
    
    return {
        "message": "Login exitoso",
        "token": token,
        "user": user
    }

# Función para verificar autenticación
def get_current_user(token: str) -> User:
    for email, user_data in users_db.items():
        if user_data.get("token") == token:
            return User(id=user_data["id"], email=email, name=user_data["name"])
    raise HTTPException(status_code=401, detail="Token inválido")

# Endpoints de Tareas
@app.get("/tasks")
async def get_tasks(token: str):
    """Obtener todas las tareas del usuario"""
    user = get_current_user(token)
    user_tasks = [task for task in tasks_db if task.user_id == user.id]
    return sorted(user_tasks, key=lambda x: x.id, reverse=True)

@app.post("/tasks")
async def create_task(task_data: TaskCreate, token: str):
    """Crear nueva tarea"""
    user = get_current_user(token)
    global current_task_id
    
    current_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
    new_task = Task(
        id=current_task_id,
        user_id=user.id,
        title=task_data.title,
        description=task_data.description,
        priority=task_data.priority,
        status=task_data.status,
        created_at=current_time,
        updated_at=current_time
    )
    
    tasks_db.append(new_task)
    current_task_id += 1
    return new_task

@app.put("/tasks/{task_id}")
async def update_task(task_id: int, task_data: TaskCreate, token: str):
    """Actualizar tarea existente"""
    user = get_current_user(token)
    
    for task in tasks_db:
        if task.id == task_id and task.user_id == user.id:
            task.title = task_data.title
            task.description = task_data.description
            task.priority = task_data.priority
            task.status = task_data.status
            task.updated_at = datetime.datetime.now().strftime("%Y-%m-%d %H:%M")
            return task
    
    raise HTTPException(status_code=404, detail="Tarea no encontrada")

@app.delete("/tasks/{task_id}")
async def delete_task(task_id: int, token: str):
    """Eliminar tarea"""
    user = get_current_user(token)
    
    for i, task in enumerate(tasks_db):
        if task.id == task_id and task.user_id == user.id:
            deleted_task = tasks_db.pop(i)
            return {"message": "Tarea eliminada", "task": deleted_task}
    
    raise HTTPException(status_code=404, detail="Tarea no encontrada")

@app.get("/tasks/{task_id}")
async def get_task(task_id: int, token: str):
    """Obtener tarea específica"""
    user = get_current_user(token)
    
    for task in tasks_db:
        if task.id == task_id and task.user_id == user.id:
            return task
    
    raise HTTPException(status_code=404, detail="Tarea no encontrada")

# Endpoints de utilidad
@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "timestamp": datetime.datetime.now().isoformat(),
        "total_users": len(users_db),
        "total_tasks": len(tasks_db)
    }

@app.post("/logout")
async def logout(token: str):
    """Cerrar sesión"""
    for user_data in users_db.values():
        if user_data.get("token") == token:
            user_data.pop("token", None)
            return {"message": "Logout exitoso"}
    
    raise HTTPException(status_code=401, detail="Token inválido")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)