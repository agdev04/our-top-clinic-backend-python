from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from sqlalchemy import and_, or_
from models import Patient, Provider, Service, Appointment
from .auth import verify_clerk_token
from .db import get_db
from typing import Optional
from datetime import datetime, timedelta, timezone

router = APIRouter()

@router.post("/")
def create_appointment(appointment_data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    # Validate required fields
    required_fields = ["provider_id", "service_id", "scheduled_time"]
    for field in required_fields:
        if field not in appointment_data:
            raise HTTPException(status_code=400, detail=f"{field} is required")
    
    # Convert scheduled_time string to datetime
    try:
        scheduled_time = datetime.fromisoformat(appointment_data["scheduled_time"].replace('Z', '+00:00'))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scheduled_time format")
    
    # Ensure appointment is not in the past
    if scheduled_time < datetime.now(timezone.utc):
        raise HTTPException(status_code=400, detail="Cannot schedule appointments in the past")
    
    # Get the service to check duration
    service = db.query(Service).filter(Service.id == appointment_data["service_id"]).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    if service.status != "active":
        raise HTTPException(status_code=400, detail="Service is not active")
    
    # Get the provider
    provider = db.query(Provider).filter(Provider.id == appointment_data["provider_id"]).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    if provider.status != "active":
        raise HTTPException(status_code=400, detail="Provider is not active")
    
    # Get the patient based on current user
    patient = db.query(Patient).filter(Patient.clerk_user_id == current_user.uid).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient profile not found")
    if patient.status != "active":
        raise HTTPException(status_code=400, detail="Patient account is not active")
    
    # Calculate appointment end time based on service duration
    end_time = scheduled_time + timedelta(minutes=service.duration_minutes)
    
    # Check for scheduling conflicts
    conflicts = db.query(Appointment).filter(
        and_(
            Appointment.provider_id == provider.id,
            Appointment.status != "cancelled",
            or_(
                and_(
                    Appointment.scheduled_time <= scheduled_time,
                    Appointment.scheduled_time + timedelta(minutes=service.duration_minutes) > scheduled_time
                ),
                and_(
                    Appointment.scheduled_time < end_time,
                    Appointment.scheduled_time + timedelta(minutes=service.duration_minutes) >= end_time
                )
            )
        )
    ).first()
    
    if conflicts:
        raise HTTPException(status_code=409, detail="Provider is not available at this time")
    
    # Create the appointment
    appointment = Appointment(
        patient_id=patient.id,
        provider_id=provider.id,
        service_id=service.id,
        scheduled_time=scheduled_time,
        status="pending",
        notes=appointment_data.get("notes")
    )
    
    db.add(appointment)
    db.commit()
    db.refresh(appointment)
    return appointment

@router.get("/")
def list_appointments(
    current_user=Depends(verify_clerk_token),
    db: Session = Depends(get_db),
    start_date: Optional[str] = None,
    end_date: Optional[str] = None,
    status: Optional[str] = None,
    provider_id: Optional[int] = None
):
    # Base query depending on user role
    if current_user.role == "admin":
        query = db.query(Appointment, Patient, Provider, Service).\
            join(Patient, Appointment.patient_id == Patient.id).\
            join(Provider, Appointment.provider_id == Provider.id).\
            join(Service, Appointment.service_id == Service.id)
    elif current_user.role == "provider":
        provider = db.query(Provider).filter(Provider.clerk_user_id == current_user.uid).first()
        if not provider:
            raise HTTPException(status_code=404, detail="Provider profile not found")
        query = db.query(Appointment, Patient, Service).\
            join(Patient, Appointment.patient_id == Patient.id).\
            join(Service, Appointment.service_id == Service.id).\
            filter(Appointment.provider_id == provider.id)
    else:  # patient
        patient = db.query(Patient).filter(Patient.clerk_user_id == current_user.uid).first()
        if not patient:
            raise HTTPException(status_code=404, detail="Patient profile not found")
        query = db.query(Appointment, Provider, Service).\
            join(Provider, Appointment.provider_id == Provider.id).\
            join(Service, Appointment.service_id == Service.id).\
            filter(Appointment.patient_id == patient.id)
    
    # Apply filters
    if start_date:
        try:
            start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
            query = query.filter(Appointment.scheduled_time >= start)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid start_date format")
    
    if end_date:
        try:
            end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
            query = query.filter(Appointment.scheduled_time <= end)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid end_date format")
    
    if status:
        query = query.filter(Appointment.status == status)
    
    if provider_id and current_user.role == "admin":
        query = query.filter(Appointment.provider_id == provider_id)
    
    # Execute query and return results
    results = query.all()
    
    appointments = []
    for appointment, *related_entities in results:
        appointment_dict = appointment.__dict__
        if current_user.role == "admin":
            patient, provider, service = related_entities
            appointment_dict["patient"] = patient.__dict__
            appointment_dict["provider"] = provider.__dict__
            appointment_dict["service"] = service.__dict__
        elif current_user.role == "provider":
            patient, service = related_entities
            appointment_dict["patient"] = patient.__dict__
            appointment_dict["service"] = service.__dict__
        else:  # patient
            provider, service = related_entities
            appointment_dict["provider"] = provider.__dict__
            appointment_dict["service"] = service.__dict__
        
        appointments.append(appointment_dict)
    
    return appointments

@router.get("/{appointment_id}")
def read_appointment(appointment_id: int, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    appointment = db.query(Appointment).filter(Appointment.id == appointment_id).first()
    if not appointment:
        raise HTTPException(status_code=404, detail="Appointment not found")
    
    # Check authorization
    if current_user.role == "provider":
        provider = db.query(Provider).filter(Provider.clerk_user_id == current_user.uid).first()
        if not provider or appointment.provider_id != provider.id:
            raise HTTPException(status_code=403, detail="Not authorized to view this appointment")
    elif current_user.role == "patient":
        patient = db.query(Patient).filter(Patient.clerk_user_id == current_user.uid).first()
        if not patient or appointment.patient_id != patient.id:
            raise HTTPException(status_code=403, detail="Not authorized to view this appointment")
    
    return appointment

@router.patch("/{appointment_id}/status")
def update_appointment_status(
    appointment_id: int,
    status_data: dict,
    current_user=Depends(verify_clerk_token),
    db: Session = Depends(get_db)
):
    if "status" not in status_data:
        raise HTTPException(status_code=400, detail="status field is required")
    
    new_status = status_data["status"]
    if new_status not in ["confirmed", "cancelled", "completed", "pending"]:
        raise HTTPException(status_code=400, detail="Invalid status value")
    
    appointment = db.query(Appointment).filter(Appointment.id == appointment_id).first()
    if not appointment:
        raise HTTPException(status_code=404, detail="Appointment not found")
    
    # Check authorization and status update permissions
    if current_user.role == "provider":
        provider = db.query(Provider).filter(Provider.clerk_user_id == current_user.uid).first()
        if not provider or appointment.provider_id != provider.id:
            raise HTTPException(status_code=403, detail="Not authorized to update this appointment")
        
        # Providers can only confirm, cancel, or mark as completed
        if new_status not in ["confirmed", "cancelled", "completed"]:
            raise HTTPException(status_code=403, detail="Providers can only confirm, cancel, or complete appointments")
    
    elif current_user.role == "patient":
        patient = db.query(Patient).filter(Patient.clerk_user_id == current_user.uid).first()
        if not patient or appointment.patient_id != patient.id:
            raise HTTPException(status_code=403, detail="Not authorized to update this appointment")
        
        # Patients can only cancel their appointments
        if new_status != "cancelled":
            raise HTTPException(status_code=403, detail="Patients can only cancel appointments")
    
    # Update the appointment status
    appointment.status = new_status
    db.commit()
    db.refresh(appointment)
    return appointment