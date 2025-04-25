from dotenv import load_dotenv
import time
import json
from fastapi import FastAPI, WebSocket, Depends
from fastapi.websockets import WebSocketState
from models import Appointment
from fastapi.middleware.cors import CORSMiddleware
import redis
from sqlalchemy.orm import Session
from routers.db import get_db
from fastapi.websockets import WebSocketDisconnect
from routers import auth, messages, patients, providers, services, commission_rates, appointments

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
async def websocket_presence(websocket: WebSocket, appointment_id: str, db: Session = Depends(get_db)):
    if not websocket.url.path.startswith("/ws/presence/"):
        await websocket.close(code=4001)
        return
    if not appointment_id or not appointment_id.isdigit():
        await websocket.close(code=4000)
        return
    # Check if appointment exists in database
    appointment = db.query(Appointment).filter(Appointment.id == int(appointment_id)).first()
    if not appointment:
        await websocket.close(code=4002)
        return
    try:
        await websocket.accept()
        redis_key = f"presence:{appointment_id}"
        # Initialize connection tracking
        connection_id = f"{appointment_id}:{websocket.client.host}:{websocket.client.port}"
        # Track connection with timestamp
        redis_client.hset(f"connections:{appointment_id}", connection_id, json.dumps({
            "host": websocket.client.host,
            "timestamp": int(time.time())
        }))
        # Set expiration for presence data
        redis_client.expire(redis_key, 86400) # 24 hours
    except Exception as e:
        print(f"WebSocket connection failed: {str(e)}")
        await websocket.close(code=5000)
        return
    
    try:
        while True:
            try:
                data = await websocket.receive_json()
                user_id = data.get('user_id')
                action = data.get('action')
                if not user_id or not action:
                    await websocket.send_json({'error': 'Missing required fields'})
                    continue
                if not isinstance(user_id, str) or not isinstance(action, str):
                    await websocket.send_json({'error': 'Invalid data types'})
                    continue
            except ValueError:
                await websocket.send_json({'error': 'Invalid JSON data'})
                continue
            
            if action == 'join':
                redis_client.sadd(redis_key, user_id)
                redis_client.hset(f"connections:{appointment_id}", connection_id, json.dumps(user_id))
            elif action == 'leave':
                redis_client.srem(redis_key, user_id)
                redis_client.hdel(f"connections:{appointment_id}", connection_id)
            elif action == 'offer':
                target_user = data.get('target_user')
                if target_user and isinstance(target_user, str):
                    await websocket.send_json({
                        'type': 'webrtc_offer',
                        'from': user_id,
                        'to': target_user,
                        'sdp': data.get('sdp')
                    })
            elif action == 'answer':
                target_user = data.get('target_user')
                if target_user and isinstance(target_user, str):
                    await websocket.send_json({
                        'type': 'webrtc_answer',
                        'from': user_id,
                        'to': target_user,
                        'sdp': data.get('sdp')
                    })
            elif action == 'ice_candidate':
                target_user = data.get('target_user')
                if not target_user or not isinstance(target_user, str):
                    await websocket.send_json({'error': 'Invalid target user for ICE candidate'})
                    continue
                if not data.get('candidate'):
                    await websocket.send_json({'error': 'Missing ICE candidate data'})
                    continue
                # Verify connection state before processing ICE candidate
                if websocket.application_state != WebSocketState.CONNECTED:
                    await websocket.send_json({'error': 'Cannot add ICE candidate - connection closed'})
                    continue
                await websocket.send_json({
                    'type': 'webrtc_ice_candidate',
                    'from': user_id,
                    'to': target_user,
                    'candidate': data.get('candidate')
                })
            
            # Broadcast presence updates to all connected clients
            current_users = [user.decode('utf-8') for user in redis_client.smembers(redis_key)]
            await websocket.send_json({
                'type': 'presence_update',
                'users': list(current_users),
                'timestamp': int(time.time())
            })
    except WebSocketDisconnect:
        try:
            if websocket.application_state == WebSocketState.CONNECTED:
                redis_client.srem(redis_key, user_id)
                redis_client.hdel(f"connections:{appointment_id}", connection_id)
                await websocket.close()
                print(f"Client disconnected: {connection_id}")
        except Exception as e:
            print(f"Error during WebSocket cleanup: {str(e)}")

# Include routers
app.include_router(auth.router, prefix="", tags=["auth"])
app.include_router(patients.router, prefix="/patients", tags=["patients"])
app.include_router(providers.router, prefix="/providers", tags=["providers"])
app.include_router(services.router, prefix="/services", tags=["services"])
app.include_router(commission_rates.router, prefix="/commission-rates", tags=["commission-rates"])
app.include_router(appointments.router, prefix="/appointments", tags=["appointments"])
app.include_router(messages.router, prefix="/messages", tags=["messages"])