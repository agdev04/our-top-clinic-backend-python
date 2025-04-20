import os
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request, Depends

load_dotenv()  # Ensure environment variables are loaded from .env in all environments
# from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from models import Provider, User, SessionLocal, Patient
from jose import jwt, JWTError
import requests
from sqlalchemy.orm import Session

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Should restrict this in production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# --- Clerk JWKS Setup ---
CLERK_JWKS_URL = os.getenv("CLERK_JWKS_URL")  # Set this to your actual JWKS URL

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_jwks():
    response = requests.get(CLERK_JWKS_URL)
    response.raise_for_status()
    return response.json()["keys"]


def get_public_key(token):
    unverified = jwt.get_unverified_header(token)
    kid = unverified.get("kid")
    if not kid:
        raise HTTPException(status_code=401, detail="Malformed token header, missing 'kid'.")
    keys = get_jwks()
    for key in keys:
        if key["kid"] == kid:
            return key
    raise HTTPException(status_code=401, detail="Public key not found for kid.")

def verify_clerk_token(request: Request, db = Depends(get_db)):
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header.")
    token = auth_header.replace("Bearer ", "")
    try:
        public_jwk = get_public_key(token)
        payload = jwt.decode(
            token,
            public_jwk,
            algorithms=public_jwk["alg"] if "alg" in public_jwk else ["RS256", "ES256"],
            options={"verify_aud": False}  # add proper audience verification for production
        )
        print("Decoded payload:", payload)
        uid = payload.get("sub")
        email = payload.get("email")

        if not uid:
            raise HTTPException(status_code=401, detail="Token did not include subject (sub).")
        user = db.query(User).filter_by(uid=uid).first()
        if not user:
            user = User(uid=uid, email=email, role="patient")
            db.add(user)
            db.commit()
            print("New user created:", user)
        
        # Ensure user has a valid role
        if not user.role or user.role not in ["patient", "provider", "admin"]:
            raise HTTPException(status_code=403, detail="Invalid user role")
            
        # Return user with clerk_uid for backward compatibility
        user.clerk_uid = uid
        return user
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid Clerk token: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token verification error: {str(e)}")


@app.get("/auth-test")
def auth_test_route(current_user=Depends(verify_clerk_token)):
    return {"message": f"Authenticated! UID: {current_user.uid}, Email: {current_user.email}"}

@app.get("/me")
def get_user_by_clerk_uid(current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.uid == current_user.uid).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    
    # Check if user is a patient or provider
    patient = db.query(Patient).filter(Patient.clerk_user_id == current_user.uid).first()
    provider = db.query(Provider).filter(Provider.clerk_user_id == current_user.uid).first()
    
    response = {
        "user": user,
        "type": "user",
        "record": None
    }
    
    if patient:
        response["type"] = "patient"
        response["record"] = patient
    elif provider:
        response["type"] = "provider"
        response["record"] = provider
    
    return response

@app.post("/patients/")
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

@app.get("/patients/{patient_id}")
def read_patient(patient_id: int, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    return patient

@app.put("/patients/{patient_id}")
def update_patient(patient_id: int, patient_data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    if patient.clerk_user_id != current_user.uid:
        raise HTTPException(status_code=403, detail="Not authorized to update this patient")
    for key, value in patient_data.items():
        setattr(patient, key, value)
    db.commit()
    db.refresh(patient)
    return patient

@app.delete("/patients/{patient_id}")
def delete_patient(patient_id: int, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    db.delete(patient)
    db.commit()
    return {"message": "Patient deleted successfully"}

@app.patch("/patients/{patient_id}/status")
def update_patient_status(patient_id: int, status_data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    patient = db.query(Patient).filter(Patient.id == patient_id).first()
    if not patient:
        raise HTTPException(status_code=404, detail="Patient not found")
    if patient.clerk_user_id != current_user.uid:
        raise HTTPException(status_code=403, detail="Not authorized to update this patient")
    if "status" not in status_data or status_data["status"] not in ["active", "inactive"]:
        raise HTTPException(status_code=400, detail="Status must be either 'active' or 'inactive'")
    
    patient.status = status_data["status"]
    db.commit()
    db.refresh(patient)
    return patient

@app.patch("/services/{service_id}/status")
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

@app.patch("/services/{service_id}/custom-rate")
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

@app.post("/register-admin")
def register_admin(data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    if "admin_password" not in data:
        raise HTTPException(status_code=400, detail="admin_password field is required")
    
    if data["admin_password"] != os.getenv("ADMIN_REGISTER_PASSWORD"):
        raise HTTPException(status_code=403, detail="Invalid admin password")
    
    current_user.role = "admin"
    db.commit()
    db.refresh(current_user)
    return {"message": "User role updated to admin successfully", "user": {"uid": current_user.uid, "email": current_user.email, "role": current_user.role}}

@app.post("/providers/")
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

@app.post("/commission-rates/")
def create_commission_rate(rate_data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can create commission rates")
    
    rate_data["admin_set"] = True
    
    # If service_id is provided, validate the service exists
    if "service_id" in rate_data:
        service = db.query(Service).filter(Service.id == rate_data["service_id"]).first()
        if not service:
            raise HTTPException(status_code=404, detail="Service not found")
    
    commission_rate = CommissionRate(**rate_data)
    db.add(commission_rate)
    db.commit()
    db.refresh(commission_rate)
    return commission_rate

@app.put("/commission-rates/{rate_id}")
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

@app.post("/services/")
def create_service(service_data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    if current_user.role != "provider":
        raise HTTPException(status_code=403, detail="Only providers can create services")
    
    # Get active commission rate for this provider
    commission_rate = db.query(CommissionRate).filter(
        CommissionRate.provider_id == service_data["provider_id"],
        CommissionRate.active == True
    ).first()
    
    if not commission_rate:
        raise HTTPException(status_code=400, detail="No active commission rate found for this provider")
    
    # Create the service
    service = Service(**service_data)
    db.add(service)
    db.commit()
    db.refresh(service)
    
    # Link the commission rate to the new service
    commission_rate.service_id = service.id
    db.commit()
    
    return service

@app.get("/providers/{provider_id}")
def read_provider(provider_id: int, db: Session = Depends(get_db)):
    provider = db.query(Provider).filter(Provider.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    return provider

@app.get("/providers/")
def search_providers(
    name: str = None,
    specialty: str = None,
    limit: int = 10,
    offset: int = 0,
    db: Session = Depends(get_db)
):
    query = db.query(Provider)
    
    if name:
        query = query.filter(
            (Provider.first_name.ilike(f"%{name}%")) | 
            (Provider.last_name.ilike(f"%{name}%"))
        )
    if specialty:
        query = query.filter(Provider.specialty.ilike(f"%{specialty}%"))
    
    total = query.count()
    providers = query.offset(offset).limit(limit).all()
    
    return {
        "total": total,
        "limit": limit,
        "offset": offset,
        "results": providers
    }

@app.put("/providers/{provider_id}")
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

@app.delete("/providers/{provider_id}")
def delete_provider(provider_id: int, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    provider = db.query(Provider).filter(Provider.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    db.delete(provider)
    db.commit()
    return {"message": "Provider deleted successfully"}

@app.patch("/providers/{provider_id}/status")
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

@app.post("/services/")
def create_service(service_data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    if current_user.role != "provider":
        raise HTTPException(status_code=403, detail="Only providers can create services")
    
    provider = db.query(Provider).filter(Provider.clerk_user_id == current_user.uid).first()
    if not provider:
        raise HTTPException(status_code=403, detail="Provider profile not found")
    
    # Get active commission rate for this provider
    commission_rate = db.query(CommissionRate).filter(
        CommissionRate.provider_id == provider.id,
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

@app.get("/services/{service_id}")
def read_service(service_id: int, db: Session = Depends(get_db)):
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    return service

@app.get("/services/")
def list_services(provider_id: int = None, db: Session = Depends(get_db)):
    query = db.query(Service)
    if provider_id:
        query = query.filter(Service.provider_id == provider_id)
    return query.all()

@app.put("/services/{service_id}")
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

@app.delete("/services/{service_id}")
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

@app.post("/commission-rates/")
def create_commission_rate(rate_data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can create commission rates")
    
    # Validate required fields
    if "provider_id" not in rate_data or "service_id" not in rate_data or "rate" not in rate_data:
        raise HTTPException(status_code=400, detail="provider_id, service_id and rate are required")
    
    # Ensure rate is between 0 and 1
    if not (0 <= rate_data["rate"] <= 1):
        raise HTTPException(status_code=400, detail="Rate must be between 0 and 1")
    
    rate = CommissionRate(**rate_data)
    db.add(rate)
    db.commit()
    db.refresh(rate)
    return rate

@app.get("/commission-rates/")
def list_commission_rates(provider_id: int = None, service_id: int = None, db: Session = Depends(get_db)):
    query = db.query(CommissionRate)
    if provider_id:
        query = query.filter(CommissionRate.provider_id == provider_id)
    if service_id:
        query = query.filter(CommissionRate.service_id == service_id)
    return query.all()

@app.patch("/commission-rates/{rate_id}/activate")
def activate_commission_rate(rate_id: int, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can activate commission rates")
    
    rate = db.query(CommissionRate).filter(CommissionRate.id == rate_id).first()
    if not rate:
        raise HTTPException(status_code=404, detail="Commission rate not found")
    
    # Deactivate all other rates for this service
    db.query(CommissionRate).filter(
        CommissionRate.service_id == rate.service_id,
        CommissionRate.active == True
    ).update({"active": False})
    
    # Activate this rate
    rate.active = True
    db.commit()
    db.refresh(rate)
    return rate

@app.delete("/commission-rates/{rate_id}")
def delete_commission_rate(rate_id: int, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can delete commission rates")
    
    rate = db.query(CommissionRate).filter(CommissionRate.id == rate_id).first()
    if not rate:
        raise HTTPException(status_code=404, detail="Commission rate not found")
    
    db.delete(rate)
    db.commit()
    return {"message": "Commission rate deleted successfully"}

@app.post("/messages/")
def send_message(message_data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can send messages")
    
    if "receiver_id" not in message_data or "content" not in message_data:
        raise HTTPException(status_code=400, detail="receiver_id and content are required")
    
    message = Message(
        sender_id=current_user.id,
        receiver_id=message_data["receiver_id"],
        content=message_data["content"]
    )
    db.add(message)
    db.commit()
    db.refresh(message)
    return message

@app.get("/messages/{receiver_id}")
def get_messages(receiver_id: int, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    if current_user.id != receiver_id and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to view these messages")
    
    messages = db.query(Message).filter(
        (Message.receiver_id == receiver_id) | 
        (Message.sender_id == receiver_id)
    ).all()
    return messages

@app.get("/messages/{message_id}/replies")
def get_message_replies(message_id: int, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    parent_message = db.query(Message).filter(Message.id == message_id).first()
    if not parent_message:
        raise HTTPException(status_code=404, detail="Parent message not found")
    
    # Ensure the current user is either sender or receiver of parent message
    if current_user.id not in [parent_message.sender_id, parent_message.receiver_id] and current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized to view these replies")
    
    replies = db.query(Message).filter(Message.parent_message_id == message_id).all()
    return replies

@app.post("/messages/{message_id}/reply")
def reply_to_message(message_id: int, message_data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    parent_message = db.query(Message).filter(Message.id == message_id).first()
    if not parent_message:
        raise HTTPException(status_code=404, detail="Parent message not found")
    
    # Determine the receiver - if current user is sender, receiver is original receiver and vice versa
    if current_user.id == parent_message.sender_id:
        receiver_id = parent_message.receiver_id
    elif current_user.id == parent_message.receiver_id:
        receiver_id = parent_message.sender_id
    else:
        raise HTTPException(status_code=403, detail="Not authorized to reply to this message")
    
    if "content" not in message_data:
        raise HTTPException(status_code=400, detail="Content is required")
    
    message = Message(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        parent_message_id=message_id,
        content=message_data["content"]
    )
    db.add(message)
    db.commit()
    db.refresh(message)
    return message
