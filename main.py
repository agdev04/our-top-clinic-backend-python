from dotenv import load_dotenv
import time
import json
import uuid
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

# Include routers
app.include_router(auth.router, prefix="", tags=["auth"])
app.include_router(patients.router, prefix="/patients", tags=["patients"])
app.include_router(providers.router, prefix="/providers", tags=["providers"])
app.include_router(services.router, prefix="/services", tags=["services"])
app.include_router(commission_rates.router, prefix="/commission-rates", tags=["commission-rates"])
app.include_router(appointments.router, prefix="/appointments", tags=["appointments"])
app.include_router(messages.router, prefix="/messages", tags=["messages"])

# WebSocket connection manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: dict[str, dict[str, WebSocket]] = {}

    async def connect(self, websocket: WebSocket, appointment_id: str, peer_id: str = None):
        await websocket.accept()
        
        if not peer_id:
            peer_id = str(uuid.uuid4())
        
        if appointment_id not in self.active_connections:
            self.active_connections[appointment_id] = {}
            
        self.active_connections[appointment_id][peer_id] = websocket
        
        # Send the peer ID back to the client
        await websocket.send_json({"type": "your_peer_id", "peer_id": peer_id})
        
        # Broadcast to other participants in this appointment
        await self.broadcast_peer_ids(appointment_id, peer_id)
        
        return peer_id

    async def disconnect(self, appointment_id: str, peer_id: str):
        if appointment_id in self.active_connections and peer_id in self.active_connections[appointment_id]:
            del self.active_connections[appointment_id][peer_id]
            await self.broadcast_peer_ids(appointment_id, peer_id)

    async def broadcast_peer_ids(self, appointment_id: str, new_peer_id: str = None):
        if appointment_id in self.active_connections:
            peer_ids = list(self.active_connections[appointment_id].keys())
            for peer_id, connection in self.active_connections[appointment_id].items():
                try:
                    await connection.send_json({
                        "type": "peer_ids_update",
                        "peer_ids": peer_ids
                    })
                except:
                    await self.disconnect(appointment_id, peer_id)

manager = ConnectionManager()

@app.websocket("/ws/{appointment_id}")
async def websocket_endpoint(websocket: WebSocket, appointment_id: str):
    # Receive peer_id from client in first message
    first_message = await websocket.receive_text()
    try:
        message = json.loads(first_message)
        peer_id = message.get('peer_id')
        if not peer_id:
            await websocket.send_json({"type": "error", "message": "peer_id is required"})
            await websocket.close()
            return
    except:
        await websocket.send_json({"type": "error", "message": "Invalid message format"})
        await websocket.close()
        return
        
    peer_id = await manager.connect(websocket, appointment_id, peer_id)
    try:
        while True:
            data = await websocket.receive_text()
            # Handle other WebSocket messages if needed
    except WebSocketDisconnect:
        await manager.disconnect(appointment_id, peer_id)