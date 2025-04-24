import os
from dotenv import load_dotenv
from fastapi import FastAPI, Depends, Request, HTTPException, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
import redis
from fastapi.websockets import WebSocketDisconnect
from models import Message, User, Patient, Provider
from routers import auth, patients, providers, services, commission_rates, appointments
import requests
from jose import jwt, JWTError

load_dotenv()  # Ensure environment variables are loaded from .env in all environments

# Redis connection
redis_client = redis.Redis(host='157.180.25.228', port=5233, db=0, password='Dc3ZLG70vD6ng9MLSxjBvHy0DdJgQXIe97Ri8B087BYh8AJqf78Fo7mCG2Z3fn5p')

app = FastAPI()

# from fastapi.middleware.httpsredirect import HTTPSRedirectMiddleware

# app.add_middleware(HTTPSRedirectMiddleware)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"], 
    allow_headers=["*"],
    expose_headers=["*"]
)

# WebSocket endpoint for user presence
@app.websocket("/ws/presence/{appointment_id}")
async def websocket_presence(websocket: WebSocket, appointment_id: str):
    await websocket.accept()
    redis_key = f"presence:{appointment_id}"
    
    try:
        while True:
            data = await websocket.receive_text()
            user_id = data.get('user_id')
            action = data.get('action')
            
            if action == 'join':
                redis_client.sadd(redis_key, user_id)
            elif action == 'leave':
                redis_client.srem(redis_key, user_id)
            
            # Broadcast presence updates to all connected clients
            current_users = redis_client.smembers(redis_key)
            await websocket.send_json({
                'type': 'presence_update',
                'users': list(current_users)
            })
    except WebSocketDisconnect:
        redis_client.srem(redis_key, user_id)
        await websocket.close()

# Include routers
app.include_router(auth.router, prefix="/auth", tags=["auth"])
app.include_router(patients.router, prefix="/patients", tags=["patients"])
app.include_router(providers.router, prefix="/providers", tags=["providers"])
app.include_router(services.router, prefix="/services", tags=["services"])
app.include_router(commission_rates.router, prefix="/commission-rates", tags=["commission-rates"])
app.include_router(appointments.router, prefix="/appointments", tags=["appointments"])

# Database session dependency imported from database module
from database import get_db

# Clerk JWKS Setup
CLERK_JWKS_URL = os.getenv("CLERK_JWKS_URL")  # Set this to your actual JWKS URL

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
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can update patient status")
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
    
    # Only allow patient to delete their own account or admin to delete any account
    if current_user.role != "admin" and patient.clerk_user_id != current_user.uid:
        raise HTTPException(status_code=403, detail="Not authorized to delete this patient")
        
    db.delete(patient)
    db.commit()
    return {"message": "Patient deleted successfully"}

@app.patch("/patients/{patient_id}/status")
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

@app.get("/patients/")
def list_patients(
    current_user=Depends(verify_clerk_token),
    db: Session = Depends(get_db),
    search: str = None,
    limit: int = 10,
    offset: int = 0,
    status: str = None
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

@app.get("/providers/")
def list_providers(
    db: Session = Depends(get_db),
    search: str = None,
    limit: int = 10,
    offset: int = 0,
    status: str = None,
    specialty: str = None
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

@app.get("/providers/{provider_id}")
def read_provider(provider_id: int, db: Session = Depends(get_db)):
    provider = db.query(Provider).filter(Provider.id == provider_id).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider not found")
    services = db.query(Service).filter(Service.provider_id == provider_id).all()
    provider_dict = provider.__dict__.copy()
    provider_dict["services"] = [service.__dict__ for service in services]
    return provider_dict

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

@app.post("/services/")
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

@app.get("/services/{service_id}")
def read_service(service_id: int, db: Session = Depends(get_db)):
    service = db.query(Service).filter(Service.id == service_id).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found")
    return service

@app.get("/services/")
def list_services(provider_id: int = None, db: Session = Depends(get_db)):
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

@app.get("/my-services/")
def list_my_services(current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    if current_user.role != "provider":
        raise HTTPException(status_code=403, detail="Only providers can access this endpoint")
    
    provider = db.query(Provider).filter(Provider.clerk_user_id == current_user.uid).first()
    if not provider:
        raise HTTPException(status_code=404, detail="Provider profile not found")
    
    services = db.query(Service).filter(Service.provider_id == provider.id).all()
    return services

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

@app.get("/commission-rates/")
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
    
    rates = query.all()
    return rates

@app.post("/commission-rates/")
def create_commission_rate(rate_data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can create commission rates")
    
    # Ensure rate is between 0 and 1
    if not (0 <= rate_data["rate"] <= 1):
        raise HTTPException(status_code=400, detail="Rate must be between 0 and 1")
    
    rate = CommissionRate(**rate_data)
    db.add(rate)
    db.commit()
    db.refresh(rate)
    return rate

@app.patch("/commission-rates/{rate_id}/activate")
def activate_commission_rate(rate_id: int, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    if current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Only admin can activate commission rates")
    
    rate = db.query(CommissionRate).filter(CommissionRate.id == rate_id).first()
    if not rate:
        raise HTTPException(status_code=404, detail="Commission rate not found")
    
    # Deactivate all other rates for this service
    db.query(CommissionRate).filter(
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
    if "receiver_id" not in message_data or "content" not in message_data:
        raise HTTPException(status_code=400, detail="receiver_id and content are required")
    
    # Validate receiver exists
    receiver = db.query(User).filter(User.id == message_data["receiver_id"]).first()
    if not receiver:
        raise HTTPException(status_code=404, detail="Receiver not found")
    
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
    # Ensure current user is either the sender or receiver of the messages
    messages = db.query(Message).filter(
        ((Message.receiver_id == receiver_id) & (Message.sender_id == current_user.id)) |
        ((Message.sender_id == receiver_id) & (Message.receiver_id == current_user.id))
    ).all()
    
    if not messages:
        raise HTTPException(status_code=404, detail="No messages found between these users")
    
    return messages

@app.get("/parent-messages/")
def get_parent_messages(current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    # Get all distinct user IDs that have interacted with current_user
    sender_ids = db.query(Message.receiver_id).filter(
        Message.sender_id == current_user.id,
        Message.parent_message_id == None
    ).distinct().all()
    
    receiver_ids = db.query(Message.sender_id).filter(
        Message.receiver_id == current_user.id,
        Message.parent_message_id == None
    ).distinct().all()
    
    # Combine and deduplicate user IDs
    user_ids = set([id[0] for id in sender_ids] + [id[0] for id in receiver_ids])
    
    # Get user details for each distinct user
    users = []
    for user_id in user_ids:
        user = db.query(User).filter(User.id == user_id).first()
        if not user:
            continue
            
        # Get user name based on role
        user_name = None
        if user.role == "patient":
            patient = db.query(Patient).filter(Patient.clerk_user_id == user.uid).first()
            if patient:
                user_name = f"{patient.first_name} {patient.last_name}"
        elif user.role == "provider":
            provider = db.query(Provider).filter(Provider.clerk_user_id == user.uid).first()
            if provider:
                user_name = f"{provider.first_name} {provider.last_name}"
                
        # Get patient or provider ID based on role
        record_id = None
        if user.role == "patient":
            patient = db.query(Patient).filter(Patient.clerk_user_id == user.uid).first()
            if patient:
                record_id = patient.id
        elif user.role == "provider":
            provider = db.query(Provider).filter(Provider.clerk_user_id == user.uid).first()
            if provider:
                record_id = provider.id
                
        users.append({
            **user.__dict__,
            "name": user_name,
            "record_id": record_id
        })
    
    return users

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


@app.post("/appointments/")
def create_appointment(appointment_data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    # Verify that the user is a patient
    patient = db.query(Patient).filter(Patient.clerk_user_id == current_user.uid).first()
    if not patient:
        raise HTTPException(status_code=403, detail="Only patients can create appointments")
    
    # Verify that the service exists and belongs to the specified provider
    service = db.query(Service).filter(
        Service.id == appointment_data["service_id"],
        Service.provider_id == appointment_data["provider_id"],
        Service.status == "active"
    ).first()
    if not service:
        raise HTTPException(status_code=404, detail="Service not found or inactive")
    
    # Convert scheduled_time string to datetime object
    try:
        scheduled_time = datetime.datetime.fromisoformat(appointment_data["scheduled_time"].replace('Z', '+00:00'))
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid datetime format")
    
    # Check for scheduling conflicts
    service_duration = datetime.timedelta(minutes=service.duration_minutes)
    appointment_end_time = scheduled_time + service_duration
    
    existing_appointment = db.query(Appointment).filter(
        Appointment.provider_id == appointment_data["provider_id"],
        Appointment.status.in_(["pending", "confirmed"]),
        and_(
            Appointment.scheduled_time < appointment_end_time,
            scheduled_time < Appointment.scheduled_time + datetime.timedelta(minutes=Appointment.service.duration_minutes)
        )
    ).first()
    
    if existing_appointment:
        raise HTTPException(status_code=400, detail="Provider is not available at this time")
    
    # Create the appointment
    new_appointment = Appointment(
        patient_id=patient.id,
        provider_id=appointment_data["provider_id"],
        service_id=appointment_data["service_id"],
        scheduled_time=scheduled_time,
        notes=appointment_data.get("notes", "")
    )
    
    db.add(new_appointment)
    db.commit()
    db.refresh(new_appointment)
    return new_appointment

@app.get("/appointments/")
def list_appointments(
    current_user=Depends(verify_clerk_token),
    db: Session = Depends(get_db),
    status: str = None,
    from_date: str = None,
    to_date: str = None
):
    # Base query depending on user role
    if current_user.role == "patient":
        patient = db.query(Patient).filter(Patient.clerk_user_id == current_user.uid).first()
        if not patient:
            raise HTTPException(status_code=404, detail="Patient profile not found")
        query = db.query(Appointment).filter(Appointment.patient_id == patient.id)
    elif current_user.role == "provider":
        provider = db.query(Provider).filter(Provider.clerk_user_id == current_user.uid).first()
        if not provider:
            raise HTTPException(status_code=404, detail="Provider profile not found")
        query = db.query(Appointment).filter(Appointment.provider_id == provider.id)
    elif current_user.role == "admin":
        query = db.query(Appointment)
    else:
        raise HTTPException(status_code=403, detail="Unauthorized")
    
    # Apply filters
    if status:
        query = query.filter(Appointment.status == status)
    
    if from_date:
        try:
            from_datetime = datetime.datetime.fromisoformat(from_date.replace('Z', '+00:00'))
            query = query.filter(Appointment.scheduled_time >= from_datetime)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid from_date format")
    
    if to_date:
        try:
            to_datetime = datetime.datetime.fromisoformat(to_date.replace('Z', '+00:00'))
            query = query.filter(Appointment.scheduled_time <= to_datetime)
        except ValueError:
            raise HTTPException(status_code=400, detail="Invalid to_date format")
    
    # Execute query and return results
    appointments = query.all()
    return appointments

@app.patch("/appointments/{appointment_id}/status")
def update_appointment_status(
    appointment_id: int,
    status_data: dict,
    current_user=Depends(verify_clerk_token),
    db: Session = Depends(get_db)
):
    if "status" not in status_data:
        raise HTTPException(status_code=400, detail="Status is required")
    
    appointment = db.query(Appointment).filter(Appointment.id == appointment_id).first()
    if not appointment:
        raise HTTPException(status_code=404, detail="Appointment not found")
    
    # Check authorization
    if current_user.role == "patient":
        patient = db.query(Patient).filter(Patient.clerk_user_id == current_user.uid).first()
        if not patient or appointment.patient_id != patient.id:
            raise HTTPException(status_code=403, detail="Not authorized")
        # Patients can only cancel their appointments
        if status_data["status"] != "cancelled":
            raise HTTPException(status_code=403, detail="Patients can only cancel appointments")
    elif current_user.role == "provider":
        provider = db.query(Provider).filter(Provider.clerk_user_id == current_user.uid).first()
        if not provider or appointment.provider_id != provider.id:
            raise HTTPException(status_code=403, detail="Not authorized")
    elif current_user.role != "admin":
        raise HTTPException(status_code=403, detail="Not authorized")
    
    appointment.status = status_data["status"]
    db.commit()
    db.refresh(appointment)
    return appointment