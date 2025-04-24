from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from models import CommissionRate
from .auth import verify_clerk_token
from .db import get_db

router = APIRouter()

@router.put("/{rate_id}")
def update_commission_rate(rate_id: int, rate_data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can update commission rates")
    
    commission_rate = db.query(CommissionRate).filter(CommissionRate.id == rate_id).first()
    if not commission_rate:
        raise HTTPException(status_code=404, detail="Commission rate not found")
    
    for key, value in rate_data.items():
        setattr(commission_rate, key, value)
    
    commission_rate.admin_set = True
    db.commit()
    db.refresh(commission_rate)
    return commission_rate

@router.get("/")
def list_commission_rates(
    provider_id: int = None,
    service_id: int = None,
    current_user=Depends(verify_clerk_token),
    db: Session = Depends(get_db)
):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can view commission rates")
    
    query = db.query(CommissionRate)
    
    if provider_id:
        query = query.filter(CommissionRate.provider_id == provider_id)
    if service_id:
        query = query.filter(CommissionRate.service_id == service_id)
    
    return query.all()