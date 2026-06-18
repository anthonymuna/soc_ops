import hmac
import hashlib
import base64
import json
import time
from fastapi import Header, HTTPException, Depends
from sqlalchemy.orm import Session
from app.database.session import get_db
from app.database.models import User
from app.config import settings

class TokenService:
    """
    Standard Base64-HMAC Token Service.
    Avoids heavy external dependencies like PyJWT/cryptography to ensure compatibility
    across offline deployments on generic Windows hardware.
    """
    
    @staticmethod
    def hash_password(password: str) -> str:
        # Secure SHA256 password hashing with salt
        salt = settings.SECRET_KEY.encode('utf-8')
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
        return base64.b64encode(hashed).decode('utf-8')

    @classmethod
    def verify_password(cls, password: str, hashed_password: str) -> bool:
        return cls.hash_password(password) == hashed_password

    @classmethod
    def create_token(cls, data: dict) -> str:
        payload = data.copy()
        # Add expiration
        payload["exp"] = time.time() + (settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60)
        
        # Serialize and encode payload
        serialized = json.dumps(payload).encode('utf-8')
        encoded_payload = base64.urlsafe_b64encode(serialized).decode('utf-8').rstrip('=')
        
        # Create signature
        signature = hmac.new(
            settings.SECRET_KEY.encode('utf-8'),
            encoded_payload.encode('utf-8'),
            hashlib.sha256
        ).digest()
        encoded_signature = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
        
        return f"{encoded_payload}.{encoded_signature}"

    @classmethod
    def decode_token(cls, token: str) -> dict:
        try:
            parts = token.split(".")
            if len(parts) != 2:
                raise ValueError("Invalid token structure")
            
            encoded_payload, encoded_signature = parts
            
            # Verify signature
            expected_signature = hmac.new(
                settings.SECRET_KEY.encode('utf-8'),
                encoded_payload.encode('utf-8'),
                hashlib.sha256
            ).digest()
            recalculated = base64.urlsafe_b64encode(expected_signature).decode('utf-8').rstrip('=')
            
            if not hmac.compare_digest(recalculated, encoded_signature):
                raise ValueError("Signature verification failed")
            
            # Pad payload for base64 decoding
            padding = len(encoded_payload) % 4
            if padding:
                encoded_payload += "=" * (4 - padding)
                
            payload_bytes = base64.urlsafe_b64decode(encoded_payload)
            payload = json.loads(payload_bytes.decode('utf-8'))
            
            # Check expiration
            if payload.get("exp", 0) < time.time():
                raise HTTPException(status_code=401, detail="Token expired")
                
            return payload
            
        except Exception:
            raise HTTPException(status_code=401, detail="Could not validate credentials")

def get_current_user(authorization: str = Header(..., alias="Authorization"), db: Session = Depends(get_db)) -> User:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Invalid authorization header format")
        
    token = authorization.split(" ")[1]
    payload = TokenService.decode_token(token)
    email = payload.get("sub")
    
    user = db.query(User).filter(User.email == email).first()
    if not user:
        raise HTTPException(status_code=401, detail="User not found")
    return user

def require_role(roles: list[str]):
    def dependency(user: User = Depends(get_current_user)):
        if user.role not in roles:
            raise HTTPException(
                status_code=403, 
                detail=f"Permission denied. Required role: {roles}"
            )
        return user
    return dependency
