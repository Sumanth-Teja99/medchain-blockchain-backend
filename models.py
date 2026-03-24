from sqlalchemy import Column, Integer, String, ForeignKey
from database import Base

# -------------------------------
# User Table
# -------------------------------
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    password = Column(String)
    role = Column(String)  # patient or doctor

# -------------------------------
# Medical Records Table
# -------------------------------
class MedicalRecord(Base):
    __tablename__ = "records"

    id = Column(Integer, primary_key=True, index=True)
    patient_id = Column(Integer, ForeignKey("users.id"))
    data = Column(String)  # encrypted data

# -------------------------------
# Record Access Table
# -------------------------------
class RecordAccess(Base):
    __tablename__ = "record_access"

    id = Column(Integer, primary_key=True, index=True)
    record_id = Column(Integer, ForeignKey("records.id"))
    doctor_id = Column(Integer, ForeignKey("users.id"))
    access_granted = Column(String)  # "yes" or "no"

# -------------------------------
# Emergency Access Table
# -------------------------------
class EmergencyAccess(Base):
    __tablename__ = "emergency_access"

    id = Column(Integer, primary_key=True, index=True)
    record_id = Column(Integer, ForeignKey("records.id"))
    doctor_id = Column(Integer, ForeignKey("users.id"))
    access_granted = Column(String)  # "yes" or "no"
    start_time = Column(String)      # start timestamp
    end_time = Column(String)        # end timestamp

# -------------------------------
# Audit Log Table
# -------------------------------
class AuditLog(Base):
    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True, index=True)
    action = Column(String)
    user_id = Column(Integer, ForeignKey("users.id"))
    record_id = Column(Integer, ForeignKey("records.id"))
    timestamp = Column(String)