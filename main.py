from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from database import engine, Base, SessionLocal
from models import User, MedicalRecord, RecordAccess
from passlib.context import CryptContext
from jose import jwt
from pydantic import BaseModel
from datetime import datetime, timedelta

# -------------------------------
# CONFIG
# -------------------------------
SECRET_KEY = "secret"
ALGORITHM = "HS256"

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

Base.metadata.create_all(bind=engine)

# -------------------------------
# DB
# -------------------------------
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# -------------------------------
# AUTH
# -------------------------------
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def create_token(user):
    return jwt.encode({
        "user_id": user.id,
        "role": user.role,
        "exp": datetime.utcnow() + timedelta(hours=10)
    }, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Header(None), db: Session = Depends(get_db)):
    if not token:
        raise HTTPException(401, "Token missing")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user = db.query(User).filter(User.id == payload["user_id"]).first()
        return user
    except:
        raise HTTPException(401, "Invalid token")

# -------------------------------
# SCHEMAS
# -------------------------------
class RegisterRequest(BaseModel):
    username: str
    password: str
    role: str

class LoginRequest(BaseModel):
    username: str
    password: str

class RecordRequest(BaseModel):
    data: str

# -------------------------------
# REGISTER
# -------------------------------
@app.post("/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(400, "User exists")

    user = User(
        username=req.username,
        password=hash_password(req.password),
        role=req.role
    )
    db.add(user)
    db.commit()
    return {"msg": "User created"}

# -------------------------------
# LOGIN
# -------------------------------
@app.post("/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()

    if not user or not verify_password(req.password, user.password):
        raise HTTPException(400, "Invalid credentials")

    return {
        "access_token": create_token(user),
        "role": user.role
    }

# -------------------------------
# ADD RECORD (PATIENT)
# -------------------------------
@app.post("/add_record")
def add_record(req: RecordRequest, user=Depends(get_current_user), db: Session = Depends(get_db)):

    if user.role != "Patient":
        raise HTTPException(403, "Only patient can add record")

    record = MedicalRecord(
        patient_id=user.id,
        data=req.data
    )
    db.add(record)
    db.commit()
    return {"msg": "Record added"}

# -------------------------------
# GET RECORDS
# -------------------------------
@app.get("/get_records")
def get_records(user=Depends(get_current_user), db: Session = Depends(get_db)):

    if user.role == "Patient":
        records = db.query(MedicalRecord).filter(
            MedicalRecord.patient_id == user.id
        ).all()
    else:
        access = db.query(RecordAccess).filter(
            RecordAccess.doctor_id == user.id
        ).all()

        ids = [a.record_id for a in access]

        records = db.query(MedicalRecord).filter(
            MedicalRecord.id.in_(ids)
        ).all()

    return [{"id": r.id, "data": r.data} for r in records]

# -------------------------------
# GRANT ACCESS
# -------------------------------
@app.post("/grant_access")
def grant_access(record_id: int, doctor_id: int, user=Depends(get_current_user), db: Session = Depends(get_db)):

    if user.role != "Patient":
        raise HTTPException(403, "Only patient can grant")

    record = db.query(MedicalRecord).filter(
        MedicalRecord.id == record_id,
        MedicalRecord.patient_id == user.id
    ).first()

    if not record:
        raise HTTPException(404, "Not found")

    db.add(RecordAccess(record_id=record_id, doctor_id=doctor_id))
    db.commit()

    return {"msg": "Access granted"}

# -------------------------------
# UPDATE RECORD
# -------------------------------
@app.put("/update_record/{record_id}")
def update_record(record_id: int, new_data: str, user=Depends(get_current_user), db: Session = Depends(get_db)):

    record = db.query(MedicalRecord).filter(MedicalRecord.id == record_id).first()

    if not record:
        raise HTTPException(404, "Not found")

    if user.role == "Patient" and record.patient_id == user.id:
        record.data = new_data

    elif user.role == "Doctor":
        access = db.query(RecordAccess).filter(
            RecordAccess.record_id == record_id,
            RecordAccess.doctor_id == user.id
        ).first()

        if not access:
            raise HTTPException(403, "No access")

        record.data = new_data
    else:
        raise HTTPException(403, "Not allowed")

    db.commit()
    return {"msg": "Updated"}

# -------------------------------
# GET DOCTORS
# -------------------------------
@app.get("/doctors")
def doctors(db: Session = Depends(get_db)):
    users = db.query(User).filter(User.role == "Doctor").all()
    return [{"id": u.id, "username": u.username} for u in users]