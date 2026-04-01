from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from database import engine, Base, SessionLocal
from models import User, MedicalRecord, RecordAccess, AuditLog
from passlib.context import CryptContext
from jose import jwt
from pydantic import BaseModel
from datetime import datetime, timedelta
import hashlib

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

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

def hash_password(password):
    return pwd_context.hash(password)

def verify_password(plain, hashed):
    return pwd_context.verify(plain, hashed)

def create_token(user):
    return jwt.encode(
        {
            "user_id": user.id,
            "role": user.role,
            "exp": datetime.utcnow() + timedelta(hours=10),
        },
        SECRET_KEY,
        algorithm=ALGORITHM,
    )

def get_current_user(token: str = Header(None), db: Session = Depends(get_db)):
    if not token:
        raise HTTPException(status_code=401, detail="Token missing")

    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user = db.query(User).filter(User.id == payload["user_id"]).first()
        if not user:
            raise HTTPException(status_code=401, detail="User not found")
        return user
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

def calculate_hash(record_id: int, patient_id: int, data: str, previous_hash: str) -> str:
    raw = f"{record_id}|{patient_id}|{data}|{previous_hash}"
    return hashlib.sha256(raw.encode()).hexdigest()

class RegisterRequest(BaseModel):
    username: str
    password: str
    role: str

class LoginRequest(BaseModel):
    username: str
    password: str

class RecordRequest(BaseModel):
    data: str

@app.get("/")
def home():
    return {"message": "MedChain Backend Running with Blockchain Integrity"}

@app.post("/register")
def register(req: RegisterRequest, db: Session = Depends(get_db)):
    if db.query(User).filter(User.username == req.username).first():
        raise HTTPException(status_code=400, detail="User exists")

    role = req.role.strip()

    user = User(
        username=req.username.strip(),
        password=hash_password(req.password),
        role=role,
    )
    db.add(user)
    db.commit()
    db.refresh(user)

    return {"msg": "User created", "user_id": user.id}

@app.post("/login")
def login(req: LoginRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == req.username.strip()).first()

    if not user or not verify_password(req.password, user.password):
        raise HTTPException(status_code=400, detail="Invalid credentials")

    return {
        "access_token": create_token(user),
        "role": user.role.lower(),
        "user_id": user.id,
        "username": user.username,
    }

@app.post("/add_record")
def add_record(req: RecordRequest, user=Depends(get_current_user), db: Session = Depends(get_db)):
    if user.role.lower() != "patient":
        raise HTTPException(status_code=403, detail=f"Only patient can add record. Your role: {user.role}")

    last_record = (
        db.query(MedicalRecord)
        .filter(MedicalRecord.patient_id == user.id)
        .order_by(MedicalRecord.id.desc())
        .first()
    )

    previous_hash = last_record.record_hash if last_record else "GENESIS"

    record = MedicalRecord(
        patient_id=user.id,
        data=req.data,
        previous_hash=previous_hash,
        record_hash="temp"
    )

    db.add(record)
    db.commit()
    db.refresh(record)

    record.record_hash = calculate_hash(
        record.id,
        record.patient_id,
        record.data,
        record.previous_hash
    )
    db.commit()
    db.refresh(record)

    audit = AuditLog(
        action="add_record",
        user_id=user.id,
        record_id=record.id,
        timestamp=str(datetime.now())
    )
    db.add(audit)
    db.commit()

    return {
        "msg": "Record added",
        "record_id": record.id,
        "record_hash": record.record_hash,
        "previous_hash": record.previous_hash,
    }

@app.get("/get_records")
def get_records(user=Depends(get_current_user), db: Session = Depends(get_db)):
    if user.role.lower() == "patient":
        records = db.query(MedicalRecord).filter(MedicalRecord.patient_id == user.id).all()
    else:
        access = db.query(RecordAccess).filter(
            RecordAccess.doctor_id == user.id,
            RecordAccess.access_granted == "yes"
        ).all()
        ids = [a.record_id for a in access]
        records = db.query(MedicalRecord).filter(MedicalRecord.id.in_(ids)).all()

    result = []
    for r in records:
        expected_hash = calculate_hash(r.id, r.patient_id, r.data, r.previous_hash)
        result.append({
            "id": r.id,
            "data": r.data,
            "previous_hash": r.previous_hash,
            "record_hash": r.record_hash,
            "verified": expected_hash == r.record_hash,
        })
    return result

@app.post("/grant_access")
def grant_access(record_id: int, doctor_id: int, user=Depends(get_current_user), db: Session = Depends(get_db)):
    if user.role.lower() != "patient":
        raise HTTPException(status_code=403, detail="Only patient can grant access")

    record = db.query(MedicalRecord).filter(
        MedicalRecord.id == record_id,
        MedicalRecord.patient_id == user.id
    ).first()

    if not record:
        raise HTTPException(status_code=404, detail="Record not found")

    existing = db.query(RecordAccess).filter(
        RecordAccess.record_id == record_id,
        RecordAccess.doctor_id == doctor_id
    ).first()

    if existing:
        existing.access_granted = "yes"
    else:
        db.add(RecordAccess(
            record_id=record_id,
            doctor_id=doctor_id,
            access_granted="yes"
        ))

    db.commit()
    return {"msg": "Access granted"}

@app.put("/update_record/{record_id}")
def update_record(record_id: int, new_data: str, user=Depends(get_current_user), db: Session = Depends(get_db)):
    record = db.query(MedicalRecord).filter(MedicalRecord.id == record_id).first()

    if not record:
        raise HTTPException(status_code=404, detail="Record not found")

    allowed = False

    if user.role.lower() == "patient" and record.patient_id == user.id:
        allowed = True

    if user.role.lower() == "doctor":
        access = db.query(RecordAccess).filter(
            RecordAccess.record_id == record_id,
            RecordAccess.doctor_id == user.id,
            RecordAccess.access_granted == "yes"
        ).first()
        if access:
            allowed = True

    if not allowed:
        raise HTTPException(status_code=403, detail="Not allowed")

    record.data = new_data
    record.record_hash = calculate_hash(
        record.id,
        record.patient_id,
        record.data,
        record.previous_hash
    )
    db.commit()

    return {
        "msg": "Updated",
        "record_hash": record.record_hash,
        "verified": True
    }

@app.get("/doctors")
def doctors(db: Session = Depends(get_db)):
    users = db.query(User).all()
    return [
        {"id": u.id, "username": u.username}
        for u in users
        if u.role.lower() == "doctor"
    ]

@app.get("/verify_chain")
def verify_chain(user=Depends(get_current_user), db: Session = Depends(get_db)):
    if user.role.lower() == "patient":
        records = db.query(MedicalRecord).filter(MedicalRecord.patient_id == user.id).order_by(MedicalRecord.id.asc()).all()
    else:
        access = db.query(RecordAccess).filter(
            RecordAccess.doctor_id == user.id,
            RecordAccess.access_granted == "yes"
        ).all()
        ids = [a.record_id for a in access]
        records = db.query(MedicalRecord).filter(MedicalRecord.id.in_(ids)).order_by(MedicalRecord.id.asc()).all()

    chain_ok = True
    details = []

    for r in records:
        expected_hash = calculate_hash(r.id, r.patient_id, r.data, r.previous_hash)
        valid = expected_hash == r.record_hash
        if not valid:
            chain_ok = False

        details.append({
            "id": r.id,
            "record_hash": r.record_hash,
            "expected_hash": expected_hash,
            "verified": valid,
        })

    return {
        "chain_valid": chain_ok,
        "total_records": len(records),
        "details": details,
    }