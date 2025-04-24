from fastapi import APIRouter, HTTPException, Request, Depends
from sqlalchemy.orm import Session
from models import User, Patient, Provider
from jose import jwt, JWTError
from .db import get_db
import requests
import os

router = APIRouter()

# --- Clerk JWKS Setup ---
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

@router.get("/auth-test")
def auth_test_route(current_user=Depends(verify_clerk_token)):
    return {"message": f"Authenticated! UID: {current_user.uid}, Email: {current_user.email}"}

@router.get("/me")
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

@router.post("/register-admin")
def register_admin(data: dict, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
    if "admin_password" not in data:
        raise HTTPException(status_code=400, detail="admin_password field is required")
    
    if data["admin_password"] != os.getenv("ADMIN_REGISTER_PASSWORD"):
        raise HTTPException(status_code=403, detail="Invalid admin password")
    
    current_user.role = "admin"
    db.commit()
    db.refresh(current_user)
    return {"message": "User role updated to admin successfully", "user": {"uid": current_user.uid, "email": current_user.email, "role": current_user.role}}