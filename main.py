from dotenv import load_dotenv
from fastapi import FastAPI, WebSocket
from fastapi.middleware.cors import CORSMiddleware
import redis
from fastapi.websockets import WebSocketDisconnect
from routers import auth, patients, providers, services, commission_rates, appointments

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
app.include_router(auth.router, prefix="", tags=["auth"])
app.include_router(patients.router, prefix="/patients", tags=["patients"])
app.include_router(providers.router, prefix="/providers", tags=["providers"])
app.include_router(services.router, prefix="/services", tags=["services"])
app.include_router(commission_rates.router, prefix="/commission-rates", tags=["commission-rates"])
app.include_router(appointments.router, prefix="/appointments", tags=["appointments"])
