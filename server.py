import logging
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from sqlalchemy import Column, Integer, String, create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
import base64
import bcrypt
from fastapi.middleware.cors import CORSMiddleware
from cryptography.hazmat.primitives.asymmetric import padding as asymmetric_padding



app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
DATABASE_URL = "sqlite:///./secure_message.db"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    password = Column(String, nullable=False)
    public_key = Column(String, nullable=False)
    private_key = Column(String, nullable=False)

class Message(Base):
    __tablename__ = "messages"
    id = Column(Integer, primary_key=True, index=True)
    sender = Column(String, nullable=False)
    recipient = Column(String, nullable=False)
    encrypted_message = Column(String, nullable=False)
    signature = Column(String, nullable=False)

Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_key_pem.decode("utf-8"), public_key_pem.decode("utf-8")

def hash_password(password):
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode("utf-8")

def verify_password(password, hashed):
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode("utf-8"))

class RegisterRequest(BaseModel):
    username: str
    password: str

class MessageRequest(BaseModel):
    sender: str
    recipient: str
    message: str

class DecryptRequest(BaseModel):
    username: str
    encrypted_message: str
    signature: str
    sender_public_key: str

@app.post("/register")
async def register_user(user: RegisterRequest, db: Session = Depends(get_db)):
    existing_user = db.query(User).filter(User.username == user.username).first()
    if existing_user:
        raise HTTPException(status_code=400, detail="Username already exists")

    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt())
    private_key, public_key = generate_key_pair()
    
    new_user = User(
        username=user.username,
        password=hashed_password,
        public_key=public_key.decode('utf-8')
    )
    db.add(new_user)
    db.commit()

    return {"message": "Registration successful", "private_key": private_key.decode('utf-8')}


@app.post("/send")
def send_message(request: MessageRequest, db: Session = Depends(get_db)):
    recipient = db.query(User).filter(User.username == request.recipient).first()
    if not recipient:
        raise HTTPException(status_code=404, detail="Recipient does not exist")

    recipient_public_key = serialization.load_pem_public_key(
        recipient.public_key.encode("utf-8"), backend=default_backend()
    )
    encrypted_message = recipient_public_key.encrypt(
        request.message.encode("utf-8"),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    sender = db.query(User).filter(User.username == request.sender).first()
    if not sender:
        raise HTTPException(status_code=404, detail="Sender does not exist")

    sender_private_key = serialization.load_pem_private_key(
        sender.private_key.encode("utf-8"), password=None, backend=default_backend()
    )
    signature = sender_private_key.sign(
        request.message.encode("utf-8"),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    new_message = Message(
        sender=request.sender,
        recipient=request.recipient,
        encrypted_message=base64.b64encode(encrypted_message).decode("utf-8"),
        signature=base64.b64encode(signature).decode("utf-8")
    )
    db.add(new_message)
    db.commit()

    return {"message": "Message sent successfully"}

@app.get("/messages/{username}")
def retrieve_messages(username: str, db: Session = Depends(get_db)):
    user_messages = db.query(Message).filter(Message.recipient == username).all()
    return [
        {
            "sender": msg.sender,
            "encrypted_message": msg.encrypted_message,
            "signature": msg.signature
        } for msg in user_messages
    ]

@app.post("/decrypt")
def decrypt_message(request: DecryptRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == request.username).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")

    try:
        user_private_key = serialization.load_pem_private_key(
            user.private_key.encode("utf-8"), password=None, backend=default_backend()
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Private key loading failed: {str(e)}")

    try:
        decrypted_message = user_private_key.decrypt(
            base64.b64decode(request.encrypted_message),
            asymmetric_padding.OAEP(
                mgf=asymmetric_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        ).decode("utf-8")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Decryption failed: {str(e)}")

    try:
        sender_public_key = serialization.load_pem_public_key(
            request.sender_public_key.encode("utf-8"), backend=default_backend()
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Sender public key loading failed: {str(e)}")

    try:
        sender_public_key.verify(
            base64.b64decode(request.signature),
            decrypted_message.encode("utf-8"),
            asymmetric_padding.PSS(
                mgf=asymmetric_padding.MGF1(hashes.SHA256()),
                salt_length=asymmetric_padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return {"message": decrypted_message, "status": "Verified"}
    except Exception as e:
        logging.exception("Signature verification failed.")
        raise HTTPException(status_code=400, detail=f"Verification failed: {str(e)}")
