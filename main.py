from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from database import engine, Base, SessionLocal
from models import User, MedicalRecord, RecordAccess, AuditLog
from passlib.context import CryptContext
from jose import jwt
from cryptography.fernet import Fernet
from pydantic import BaseModel
import hashlib
from datetime import datetime, timedelta

# -------------------------------
# CONFIG
# -------------------------------
SECRET_KEY = "mysecretkey"
ALGORITHM = "HS256"

# -------------------------------
# APP
# -------------------------------
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
# ENCRYPTION
# -------------------------------
key = Fernet.generate_key()
cipher = Fernet(key)

def encrypt_data(data: str):
    return cipher.encrypt(data.encode()).decode()

def decrypt_data(data: str):
    return cipher.decrypt(data.encode()).decode()

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

def get_current_user(token: str = Header(...), db: Session = Depends(get_db)):
    try:
        token = token.replace("Bearer ", "")
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user = db.query(User).filter(User.id == payload["user_id"]).first()
        return user
    except:
        raise HTTPException(status_code=401, detail="Invalid Token")

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
# RESET USERS
# -------------------------------
@app.on_event("startup")
def reset_users():
    db = SessionLocal()

    db.query(User).delete()
    db.commit()

    users = [
        User(username="patient1", password=hash_password("1234"), role="Patient"),
        User(username="doctor1", password=hash_password("1234"), role="Doctor"),
    ]

    db.add_all(users)
    db.commit()
    db.close()

# -------------------------------
# HOME
# -------------------------------
@app.get("/")
def home():
    return {"message": "MedChain Backend Running 🚀"}

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
    db.refresh(user)

    return {"msg": "User created", "user_id": user.id}

# -------------------------------
# LOGIN
# -------------------------------
@app.post("/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username).first()

    if not user or not verify_password(req.password, user.password):
        raise HTTPException(400, "Invalid credentials")

    token = create_token(user)

    return {
        "access_token": token,
        "role": user.role,
        "user_id": user.id
    }

# -------------------------------
# ADD RECORD (PATIENT ONLY)
# -------------------------------
@app.post("/add_record")
def add_record(req: RecordRequest, user=Depends(get_current_user), db: Session = Depends(get_db)):

    if user.role != "Patient":
        raise HTTPException(403, "Only patient can add record")

    encrypted = encrypt_data(req.data)

    record = MedicalRecord(
        patient_id=user.id,
        data=encrypted
    )

    db.add(record)
    db.commit()
    db.refresh(record)

    db.add(AuditLog(
        action="add_record",
        user_id=user.id,
        record_id=record.id,
        timestamp=str(datetime.now())
    ))
    db.commit()

    return {"msg": "Record added", "record_id": record.id}

# -------------------------------
# GET RECORDS
# -------------------------------
@app.get("/get_records")
def get_records(user=Depends(get_current_user), db: Session = Depends(get_db)):

    if user.role == "Patient":
        records = db.query(MedicalRecord).filter(
            MedicalRecord.patient_id == user.id
        ).all()

    else:  # Doctor
        allowed = db.query(RecordAccess).filter(
            RecordAccess.doctor_id == user.id,
            RecordAccess.access_granted == "yes"
        ).all()

        record_ids = [a.record_id for a in allowed]

        records = db.query(MedicalRecord).filter(
            MedicalRecord.id.in_(record_ids)
        ).all()

    result = []
    for r in records:
        result.append({
            "id": r.id,
            "data": decrypt_data(r.data)
        })

    return result

# -------------------------------
# GRANT ACCESS
# -------------------------------
@app.post("/grant_access")
def grant_access(record_id: int, doctor_id: int, user=Depends(get_current_user), db: Session = Depends(get_db)):

    if user.role != "Patient":
        raise HTTPException(403, "Only patient can grant access")

    record = db.query(MedicalRecord).filter(
        MedicalRecord.id == record_id,
        MedicalRecord.patient_id == user.id
    ).first()

    if not record:
        raise HTTPException(404, "Record not found")

    access = RecordAccess(
        record_id=record_id,
        doctor_id=doctor_id,
        access_granted="yes"
    )

    db.add(access)
    db.commit()

    return {"msg": "Access granted"}