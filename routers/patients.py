from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from models import User, Patient
from .auth import verify_clerk_token
from .db import get_db
from typing import Optional

router = APIRouter()

@router.post("/")
def create_patient(patient_data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    # Automatically set clerk_user_id from the authenticated user
    patient_data["clerk_user_id"] = current_user.uid
    patient = Patient(**patient_data)
    db.add(patient)

    # Update user role to provider
    current_user.role = "provider"

    db.commit()
    db.refresh(patient)
    db.refresh(current_user)
    return patient

@router.get("/{patient_id}")
def read_patient(patient_id: int, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    return patient

@router.put("/{patient_id}")
def update_patient(patient_id: int, patient_data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can update patient status")
    for key, value in patient_data.items():
        setattr(patient, key, value)
    db.commit()
    db.refresh(patient)
    return patient

@router.delete("/{patient_id}")
def delete_patient(patient_id: int, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    
    # Only allow patient to delete their own account or admin to delete any account
    if current_user.role != "admin" and patient.clerk_user_id != current_user.uid:
        raise HTTPException(status_code=403, detail="Not authorized to delete this patient")
        
    db.delete(patient)
    db.commit()
    return {"message": "Patient deleted successfully"}

@router.patch("/{patient_id}/status")
def update_patient_status(patient_id: int, status_data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can update patient status")
    if "status" not in status_data or status_data["status"] not in ["active", "inactive"]:
        raise HTTPException(status_code=400, detail="Status must be either 'active' or 'inactive'")
    
    patient.status = status_data["status"]
    db.commit()
    db.refresh(patient)
    return patient

@router.get("/")
def list_patients(
    current_user=Depends(verify_clerk_token),
    db: Session = Depends(get_db),
    search: Optional[str] = None,
    limit: int = 10,
    offset: int = 0,
    status: Optional[str] = None
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can view all patients")
    
    query = db.query(Patient, User.id.label("user_id"), User.email).join(User, Patient.clerk_user_id == User.uid)
    
    if search:
        query = query.filter(
            Patient.first_name.ilike(f"%{search}%") |
            Patient.last_name.ilike(f"%{search}%") |
            Patient.phone_number.ilike(f"%{search}%") |
            User.email.ilike(f"%{search}%")
        )
    
    if status and status in ["active", "inactive"]:
        query = query.filter(Patient.status == status)
    
    total = query.count()
    results = query.offset(offset).limit(limit).all()
    
    patients = []
    for patient, user_id, email in results:
        patient_dict = patient.__dict__
        patient_dict["user_id"] = user_id
        patient_dict["email"] = email
        patients.append(patient_dict)
    
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "patients": patients
    }