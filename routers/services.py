from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from models import Provider, Service, CommissionRate
from .auth import verify_clerk_token
from .db import get_db
from typing import Optional

router = APIRouter()

@router.post("/")
def create_service(service_data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    if current_user.role != "provider":
        raise HTTPException(status_code=403, detail="Only providers can create services")
    
    provider = db.query(Provider).filter(Provider.clerk_user_id == current_user.uid).first()
    if not provider:
        raise HTTPException(status_code=403, detail="Provider profile not found")
    
    # Get active commission rate for this provider
    commission_rate = db.query(CommissionRate).filter(
        CommissionRate.active == True
    ).first()
    
    service_data["provider_id"] = provider.id
    if commission_rate:
        service_data["commission_rate_id"] = commission_rate.id
    
    service = Service(**service_data)
    db.add(service)
    db.commit()
    db.refresh(service)
    return service

@router.get("/{service_id}")
def read_service(service_id: int, db: Session = Depends(get_db)):
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    return service

@router.get("/")
def list_services(provider_id: Optional[int] = None, db: Session = Depends(get_db)):
    query = db.query(Service, Provider).join(Provider, Service.provider_id == Provider.id)
    if provider_id:
        query = query.filter(Service.provider_id == provider_id)
    
    results = query.all()
    return [
        {
            **service.__dict__,
            "provider": {
                "id": provider.id,
                "first_name": provider.first_name,
                "last_name": provider.last_name,
                "specialty": provider.specialty,
                "status": provider.status
            }
        }
        for service, provider in results
    ]

@router.get("/my-services/")
def list_my_services(current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    if current_user.role != "provider":
        raise HTTPException(status_code=403, detail="Only providers can access this endpoint")
    
    provider = db.query(Provider).filter(Provider.clerk_user_id == current_user.uid).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider profile not found")
    
    services = db.query(Service).filter(Service.provider_id == provider.id).all()
    return services

@router.put("/{service_id}")
def update_service(service_id: int, service_data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    if current_user.role != "provider":
        raise HTTPException(status_code=403, detail="Only providers can update services")
    
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    provider = db.query(Provider).filter(Provider.clerk_user_id == current_user.uid).first()
    if not provider or service.provider_id != provider.id:
        raise HTTPException(status_code=403, detail="Not authorized to update this service")
    
    # Only admin can change status
    if "status" in service_data and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can update service status")
        
    for key, value in service_data.items():
        setattr(service, key, value)
    db.commit()
    db.refresh(service)
    return service

@router.delete("/{service_id}")
def delete_service(service_id: int, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    if current_user.role != "provider":
        raise HTTPException(status_code=403, detail="Only providers can delete services")
    
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    provider = db.query(Provider).filter(Provider.clerk_user_id == current_user.uid).first()
    if not provider or service.provider_id != provider.id:
        raise HTTPException(status_code=403, detail="Not authorized to delete this service")
    
    db.delete(service)
    db.commit()
    return {"message": "Service deleted successfully"}

@router.patch("/{service_id}/custom-rate")
def update_service_custom_rate(service_id: int, rate_data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can update custom rates")
    
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    if "custom_rate" not in rate_data or not isinstance(rate_data["custom_rate"], (float, int)):
        raise HTTPException(status_code=400, detail="custom_rate must be a number")
    
    service.custom_rate = rate_data["custom_rate"]
    db.commit()
    db.refresh(service)
    return service

@router.patch("/{service_id}/status")
def update_service_status(service_id: int, status_data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can update service status")
    
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    
    if "status" not in status_data or status_data["status"] not in ["active", "inactive"]:
        raise HTTPException(status_code=400, detail="Status must be either 'active' or 'inactive'")
    
    service.status = status_data["status"]
    db.commit()
    db.refresh(service)
    return service