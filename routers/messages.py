from fastapi import APIRouter, HTTPException, Depends
from sqlalchemy.orm import Session
from models import Message, Patient, Provider, User
from .auth import verify_clerk_token
from .db import get_db

router = APIRouter()

@router.post("/")
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
 
@router.get("/{receiver_id}")
def get_messages(receiver_id: int, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
     # Ensure current user is either the sender or receiver of the messages
     messages = db.query(Message).filter(
         ((Message.receiver_id == receiver_id) & (Message.sender_id == current_user.id)) |
         ((Message.sender_id == receiver_id) & (Message.receiver_id == current_user.id))
     ).all()
     
     if not messages:
         raise HTTPException(status_code=404, detail="No messages found between these users")
     
     return messages
 
@router.get("/parent-messages/")
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
 
@router.get("/{message_id}/replies")
def get_message_replies(message_id: int, current_user=Depends(verify_clerk_token), db: Session = Depends(get_db)):
     parent_message = db.query(Message).filter(Message.id == message_id).first()
     if not parent_message:
         raise HTTPException(status_code=404, detail="Parent message not found")
     
     # Ensure the current user is either sender or receiver of parent message
     if current_user.id not in [parent_message.sender_id, parent_message.receiver_id] and current_user.role != "admin":
         raise HTTPException(status_code=403, detail="Not authorized to view these replies")
     
     replies = db.query(Message).filter(Message.parent_message_id == message_id).all()
     return replies
 
@router.post("/{message_id}/reply")
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