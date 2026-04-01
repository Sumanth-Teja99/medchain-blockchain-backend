from sqlalchemy import Column, Integer, String, ForeignKey
from database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    role = Column(String)

class MedicalRecord(Base):
    __tablename__ = "medical_records"

    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("users.id"))
    data = Column(String)
    previous_hash = Column(String, default="GENESIS")
    record_hash = Column(String, nullable=False)

class RecordAccess(Base):
    __tablename__ = "record_access"

    id = Column(Integer, primary_key=True, index=True)
    record_id = Column(Integer, ForeignKey("medical_records.id"))
    doctor_id = Column(Integer, ForeignKey("users.id"))
    access_granted = Column(String, default="yes")

class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    action = Column(String)
    user_id = Column(Integer)
    record_id = Column(Integer)
    timestamp = Column(String)