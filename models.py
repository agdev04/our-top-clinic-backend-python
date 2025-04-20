from dotenv import load_dotenv
load_dotenv()
import os
from sqlalchemy import create_engine, Column, Integer, String, Enum, Float, Date, String, ForeignKey, DateTime, Boolean, ARRAY
from sqlalchemy.orm import sessionmaker, declarative_base, relationship
import datetime
from enum import Enum as PyEnum

DATABASE_URL = os.getenv("DATABASE_URL")
if DATABASE_URL and DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql+psycopg2://", 1)
engine = create_engine(DATABASE_URL, pool_recycle=280, pool_pre_ping=True)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class ContactMethod(PyEnum):
    EMAIL = "Email"
    PHONE = "Phone"
    TEXT_MESSAGE = "Text Message"

class AppointmentType(PyEnum):
    TELEHEALTH = "Telehealth Only"
    IN_PERSON = "In-Person Only"
    BOTH = "Both"

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    uid = Column(String, unique=True, index=True)
    email = Column(String)
    role = Column(String, default="patient")

class Patient(Base):
    __tablename__ = "patients"
    
    id = Column(Integer, primary_key=True, index=True)
    clerk_user_id = Column(String(255), nullable=False)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    phone_number = Column(String(20), nullable=False)
    date_of_birth = Column(Date, nullable=False)
    gender = Column(String(50), nullable=False)
    height = Column(Float, nullable=False)
    weight = Column(Float, nullable=False)
    address = Column(String(255), nullable=False)
    city = Column(String(100), nullable=False)
    state = Column(String(100), nullable=False)
    zip_code = Column(String(20), nullable=False)
    preferred_contact_method = Column(String(20), nullable=False)
    preferred_appointment_type = Column(String(20), nullable=False)
    status = Column(String(20), nullable=False, default="active")
    created_at = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class Provider(Base):
    __tablename__ = "providers"
    
    id = Column(Integer, primary_key=True, index=True)
    clerk_user_id = Column(String(255), nullable=False)
    first_name = Column(String(100), nullable=False)
    last_name = Column(String(100), nullable=False)
    phone_number = Column(String(20), nullable=False)
    practice_address = Column(String(255), nullable=False)
    city = Column(String(100), nullable=False)
    state = Column(String(100), nullable=False)
    zip_code = Column(String(20), nullable=False)
    license_number = Column(String(100), nullable=False)
    npi = Column(String(20), nullable=False)
    specialty = Column(String(100), nullable=False)
    years_in_practice = Column(Integer, nullable=False)
    board_certified = Column(Boolean, nullable=False, default=False)
    accepting_new_patients = Column(Boolean, nullable=False, default=False)
    license_documents = Column(ARRAY(String), nullable=True)
    digital_signature = Column(String(255), nullable=True)
    status = Column(String(20), nullable=False, default="inactive")
    created_at = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class Service(Base):
    __tablename__ = "services"
    
    id = Column(Integer, primary_key=True, index=True)
    provider_id = Column(Integer, ForeignKey("providers.id"), nullable=False)
    commission_rate_id = Column(Integer, ForeignKey("commission_rates.id"), nullable=True)
    custom_rate = Column(Float, nullable=True)
    name = Column(String(100), nullable=False)
    category = Column(String(100), nullable=False)
    description = Column(String(500), nullable=False)
    price = Column(Float, nullable=False)
    duration_minutes = Column(Integer, nullable=False)
    status = Column(String(20), nullable=False, default="inactive")
    created_at = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class CommissionRate(Base):
    __tablename__ = "commission_rates"
    
    id = Column(Integer, primary_key=True, index=True)
    provider_id = Column(Integer, ForeignKey("providers.id"), nullable=False)
    rate = Column(Float, nullable=False)
    active = Column(Boolean, default=False)
    created_at = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.datetime.utcnow, onupdate=datetime.datetime.utcnow)

class Message(Base):
    __tablename__ = "messages"
    
    id = Column(Integer, primary_key=True, index=True)
    sender_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    receiver_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    parent_message_id = Column(Integer, ForeignKey("messages.id"), nullable=True)
    content = Column(String(1000), nullable=False)
    is_read = Column(Boolean, default=False)
    created_at = Column(DateTime, nullable=False, default=datetime.datetime.utcnow)
    
    sender = relationship("User", foreign_keys=[sender_id])
    receiver = relationship("User", foreign_keys=[receiver_id])
    parent_message = relationship("Message", remote_side=[id], backref="replies")

Base.metadata.create_all(bind=engine)