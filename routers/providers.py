from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from models import User, Provider, Service, Appointment
from .auth import verify_clerk_token
from .db import get_db
from typing import Optional

router = APIRouter()

@router.post("/")
def create_provider(provider_data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    provider_data["clerk_user_id"] = current_user.uid
    provider = Provider(**provider_data)
    db.add(provider)
    
    # Update user role to provider
    current_user.role = "provider"
    
    db.commit()
    db.refresh(provider)
    db.refresh(current_user)
    return provider

@router.get("/{provider_id}")
def read_provider(provider_id: int, db: Session = Depends(get_db)):
    provider = db.query(Provider).filter(Provider.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    services = db.query(Service).filter(Service.provider_id == provider_id).all()
    appointments = db.query(Appointment).filter(Appointment.provider_id == provider_id).all()
    
    provider_dict = provider.__dict__.copy()
    provider_dict["services"] = [service.__dict__ for service in services]
    provider_dict["appointments"] = [appointment.__dict__ for appointment in appointments]
    return provider_dict

@router.put("/{provider_id}")
def update_provider(provider_id: int, provider_data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    provider = db.query(Provider).filter(Provider.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    if provider.clerk_user_id != current_user.uid and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to update this provider")
    
    # Only admin can change status
    if "status" in provider_data and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can update provider status")
        
    for key, value in provider_data.items():
        setattr(provider, key, value)
    db.commit()
    db.refresh(provider)
    return provider

@router.delete("/{provider_id}")
def delete_provider(provider_id: int, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    provider = db.query(Provider).filter(Provider.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    db.delete(provider)
    db.commit()
    return {"message": "Provider deleted successfully"}

@router.patch("/{provider_id}/status")
def update_provider_status(provider_id: int, status_data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can update provider status")
    
    provider = db.query(Provider).filter(Provider.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    
    if "status" not in status_data or status_data["status"] not in ["active", "inactive"]:
        raise HTTPException(status_code=400, detail="Status must be either 'active' or 'inactive'")
    
    provider.status = status_data["status"]
    db.commit()
    db.refresh(provider)
    return provider

@router.get("/")
def list_providers(
    db: Session = Depends(get_db),
    search: Optional[str] = None,
    limit: int = 10,
    offset: int = 0,
    status: Optional[str] = None,
    specialty: Optional[str] = None
):
    query = db.query(Provider, User.id.label("user_id"), User.email).join(User, Provider.clerk_user_id == User.uid)
    
    if search:
        query = query.filter(
            Provider.first_name.ilike(f"%{search}%") |
            Provider.last_name.ilike(f"%{search}%") |
            Provider.phone_number.ilike(f"%{search}%") |
            Provider.specialty.ilike(f"%{search}%")
        )
    
    if status and status in ["active", "inactive"]:
        query = query.filter(Provider.status == status)
        
    if specialty:
        query = query.filter(Provider.specialty.ilike(f"%{specialty}%"))
    
    total = query.count()
    results = query.offset(offset).limit(limit).all()
    
    providers = []
    for provider, user_id, email in results:
        provider_dict = provider.__dict__
        provider_dict["user_id"] = user_id
        provider_dict["email"] = email
        # Add services for each provider
        services = db.query(Service).filter(Service.provider_id == provider.id).all()
        provider_dict["services"] = [service.__dict__ for service in services]
        providers.append(provider_dict)
    
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "providers": providers
    }