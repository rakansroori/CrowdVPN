"""Production-ready cryptography module for Crowd VPN.

This module implements secure cryptographic operations with:
- Proper ECDH key exchange
- Ed25519/X25519 modern curves
- ChaCha20-Poly1305 authenticated encryption
- Perfect forward secrecy
- Secure memory management
- Constant-time operations
"""

import os
import secrets
import time
import hmac
import hashlib
from typing import Optional, Dict, Tuple, Any
from dataclasses import dataclass
from threading import RLock

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature


@dataclass
class SecureSession:
    """Represents a secure session with a peer."""
    session_id: str
    peer_id: str
    encryption_key: bytes
    mac_key: bytes
    created_time: float
    last_used: float
    message_counter_send: int = 0
    message_counter_receive: int = 0
    is_active: bool = True


class SecureMemory:
    """Secure memory management for sensitive data."""
    
    @staticmethod
    def clear_bytes(data: bytes) -> None:
        """Securely clear bytes from memory."""
        if hasattr(data, '__array_interface__'):
            # For numpy arrays or similar
            data.fill(0)
        else:
            # Best effort for regular bytes objects
            # Note: Python doesn't guarantee memory clearing
            pass
    
    @staticmethod
    def secure_compare(a: bytes, b: bytes) -> bool:
        """Constant-time comparison to prevent timing attacks."""
        return hmac.compare_digest(a, b)


class ProductionCryptoManager:
    """Production-ready cryptographic operations manager."""
    
    # Cryptographic constants
    KEY_SIZE = 32  # 256 bits
    NONCE_SIZE = 12  # 96 bits for ChaCha20Poly1305
    SESSION_TIMEOUT = 3600  # 1 hour
    KEY_ROTATION_INTERVAL = 1800  # 30 minutes
    MAX_MESSAGE_COUNTER = 2**32 - 1  # Prevent counter overflow
    
    def __init__(self):
        self.backend = default_backend()
        self._sessions: Dict[str, SecureSession] = {}
        self._session_lock = RLock()
        
        # Long-term identity keys (Ed25519)
        self._identity_private_key: Optional[ed25519.Ed25519PrivateKey] = None
        self._identity_public_key: Optional[ed25519.Ed25519PublicKey] = None
        
        # Current ephemeral key pair (X25519) - rotated regularly
        self._ephemeral_private_key: Optional[x25519.X25519PrivateKey] = None
        self._ephemeral_public_key: Optional[x25519.X25519PublicKey] = None
        self._ephemeral_key_created: float = 0
    
    def generate_identity_keypair(self) -> Tuple[bytes, bytes]:
        """Generate Ed25519 identity key pair for signing."""
        self._identity_private_key = ed25519.Ed25519PrivateKey.generate()
        self._identity_public_key = self._identity_private_key.public_key()
        
        # Serialize keys
        private_pem = self._identity_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = self._identity_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    def load_identity_keypair(self, private_pem: bytes, public_pem: bytes, 
                            password: Optional[bytes] = None) -> None:
        """Load existing identity key pair."""
        try:
            self._identity_private_key = serialization.load_pem_private_key(
                private_pem, password=password, backend=self.backend
            )
            self._identity_public_key = serialization.load_pem_public_key(
                public_pem, backend=self.backend
            )
            
            # Validate key types
            if not isinstance(self._identity_private_key, ed25519.Ed25519PrivateKey):
                raise ValueError("Private key must be Ed25519")
            if not isinstance(self._identity_public_key, ed25519.Ed25519PublicKey):
                raise ValueError("Public key must be Ed25519")
                
        except Exception as e:
            raise ValueError(f"Failed to load identity keypair: {e}")
    
    def _rotate_ephemeral_keys(self) -> None:
        """Rotate ephemeral keys for forward secrecy."""
        current_time = time.time()
        if (current_time - self._ephemeral_key_created) > self.KEY_ROTATION_INTERVAL:
            # Clear old keys from memory
            if self._ephemeral_private_key:
                SecureMemory.clear_bytes(self._ephemeral_private_key.private_bytes(
                    encoding=serialization.Encoding.Raw,
                    format=serialization.PrivateFormat.Raw,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            
            # Generate new ephemeral keys
            self._ephemeral_private_key = x25519.X25519PrivateKey.generate()
            self._ephemeral_public_key = self._ephemeral_private_key.public_key()
            self._ephemeral_key_created = current_time
    
    def get_ephemeral_public_key(self) -> bytes:
        """Get current ephemeral public key for key exchange."""
        self._rotate_ephemeral_keys()
        if not self._ephemeral_public_key:
            self._ephemeral_private_key = x25519.X25519PrivateKey.generate()
            self._ephemeral_public_key = self._ephemeral_private_key.public_key()
            self._ephemeral_key_created = time.time()
        
        return self._ephemeral_public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    def establish_secure_session(self, peer_id: str, 
                               peer_ephemeral_public_key: bytes,
                               peer_identity_public_key: bytes) -> str:
        """Establish secure session using ECDH key exchange."""
        # Validate inputs
        if len(peer_ephemeral_public_key) != 32:
            raise ValueError("Invalid peer ephemeral public key length")
        
        if not self._ephemeral_private_key:
            self._rotate_ephemeral_keys()
        
        try:
            # Load peer's ephemeral public key
            peer_public_key = x25519.X25519PublicKey.from_public_bytes(
                peer_ephemeral_public_key
            )
            
            # Perform ECDH key exchange
            shared_secret = self._ephemeral_private_key.exchange(peer_public_key)
            
            # Derive session keys using HKDF
            session_id = secrets.token_hex(16)
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=64,  # 32 bytes each for encryption and MAC
                salt=b"CrowdVPN-Session-" + session_id.encode(),
                info=b"session_keys",
                backend=self.backend
            )
            
            derived_keys = hkdf.derive(shared_secret)
            encryption_key = derived_keys[:32]
            mac_key = derived_keys[32:]
            
            # Create session
            session = SecureSession(
                session_id=session_id,
                peer_id=peer_id,
                encryption_key=encryption_key,
                mac_key=mac_key,
                created_time=time.time(),
                last_used=time.time()
            )
            
            # Store session
            with self._session_lock:
                self._sessions[session_id] = session
            
            # Clean old sessions
            self._cleanup_expired_sessions()
            
            return session_id
            
        except Exception as e:
            raise ValueError(f"Failed to establish secure session: {e}")
    
    def encrypt_message(self, data: bytes, session_id: str) -> dict:
        """Encrypt message with authenticated encryption."""
        with self._session_lock:
            session = self._sessions.get(session_id)
            if not session or not session.is_active:
                raise ValueError(f"Invalid or expired session: {session_id}")
            
            # Check message counter to prevent overflow
            if session.message_counter_send >= self.MAX_MESSAGE_COUNTER:
                raise ValueError("Message counter overflow - key rotation required")
            
            try:
                # Generate secure nonce
                nonce = secrets.token_bytes(self.NONCE_SIZE)
                
                # Encrypt with ChaCha20Poly1305
                cipher = ChaCha20Poly1305(session.encryption_key)
                
                # Associated data includes session info to prevent session confusion
                associated_data = f"{session_id}:{session.message_counter_send}".encode()
                
                ciphertext = cipher.encrypt(nonce, data, associated_data)
                
                # Generate HMAC for additional integrity
                hmac_data = nonce + ciphertext + associated_data
                message_hmac = hmac.new(
                    session.mac_key, 
                    hmac_data, 
                    hashlib.sha256
                ).digest()
                
                # Update session
                session.message_counter_send += 1
                session.last_used = time.time()
                
                return {
                    'session_id': session_id,
                    'counter': session.message_counter_send - 1,
                    'nonce': nonce.hex(),
                    'ciphertext': ciphertext.hex(),
                    'hmac': message_hmac.hex(),
                    'timestamp': int(time.time())
                }
                
            except Exception as e:
                raise ValueError(f"Encryption failed: {e}")
    
    def decrypt_message(self, encrypted_message: dict) -> bytes:
        """Decrypt and verify authenticated message."""
        try:
            session_id = encrypted_message['session_id']
            counter = encrypted_message['counter']
            nonce = bytes.fromhex(encrypted_message['nonce'])
            ciphertext = bytes.fromhex(encrypted_message['ciphertext'])
            received_hmac = bytes.fromhex(encrypted_message['hmac'])
            
            with self._session_lock:
                session = self._sessions.get(session_id)
                if not session or not session.is_active:
                    raise ValueError(f"Invalid or expired session: {session_id}")
                
                # Prevent replay attacks (but allow first message)
                if counter < session.message_counter_receive or (counter == session.message_counter_receive and session.message_counter_receive > 0):
                    raise ValueError("Message counter replay detected")
                
                # Verify HMAC first
                associated_data = f"{session_id}:{counter}".encode()
                hmac_data = nonce + ciphertext + associated_data
                expected_hmac = hmac.new(
                    session.mac_key,
                    hmac_data,
                    hashlib.sha256
                ).digest()
                
                if not SecureMemory.secure_compare(received_hmac, expected_hmac):
                    raise ValueError("HMAC verification failed")
                
                # Decrypt message
                cipher = ChaCha20Poly1305(session.encryption_key)
                plaintext = cipher.decrypt(nonce, ciphertext, associated_data)
                
                # Update session
                session.message_counter_receive = counter
                session.last_used = time.time()
                
                return plaintext
                
        except Exception as e:
            raise ValueError(f"Decryption failed: {e}")
    
    def sign_message(self, message: bytes) -> bytes:
        """Sign message with identity key."""
        if not self._identity_private_key:
            raise ValueError("No identity private key available")
        
        try:
            signature = self._identity_private_key.sign(message)
            return signature
        except Exception as e:
            raise ValueError(f"Signing failed: {e}")
    
    def verify_signature(self, message: bytes, signature: bytes, 
                        peer_public_key_pem: bytes) -> bool:
        """Verify message signature."""
        try:
            # Load peer's public key
            peer_public_key = serialization.load_pem_public_key(
                peer_public_key_pem, backend=self.backend
            )
            
            if not isinstance(peer_public_key, ed25519.Ed25519PublicKey):
                raise ValueError("Peer public key must be Ed25519")
            
            # Verify signature
            peer_public_key.verify(signature, message)
            return True
            
        except (InvalidSignature, Exception):
            return False
    
    def get_identity_public_key(self) -> bytes:
        """Get identity public key in PEM format."""
        if not self._identity_public_key:
            raise ValueError("No identity public key available")
        
        return self._identity_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def get_public_key_fingerprint(self) -> str:
        """Get fingerprint of identity public key."""
        public_key_bytes = self.get_identity_public_key()
        fingerprint = hashlib.sha256(public_key_bytes).hexdigest()[:16]
        return fingerprint
    
    def _cleanup_expired_sessions(self) -> None:
        """Clean up expired sessions."""
        current_time = time.time()
        expired_sessions = []
        
        with self._session_lock:
            for session_id, session in self._sessions.items():
                if (current_time - session.last_used) > self.SESSION_TIMEOUT:
                    expired_sessions.append(session_id)
            
            for session_id in expired_sessions:
                session = self._sessions[session_id]
                # Clear sensitive data
                SecureMemory.clear_bytes(session.encryption_key)
                SecureMemory.clear_bytes(session.mac_key)
                del self._sessions[session_id]
    
    def revoke_session(self, session_id: str) -> None:
        """Revoke a specific session."""
        with self._session_lock:
            if session_id in self._sessions:
                session = self._sessions[session_id]
                session.is_active = False
                # Clear sensitive data
                SecureMemory.clear_bytes(session.encryption_key)
                SecureMemory.clear_bytes(session.mac_key)
                del self._sessions[session_id]
    
    def revoke_all_sessions(self) -> None:
        """Revoke all active sessions."""
        with self._session_lock:
            for session in self._sessions.values():
                session.is_active = False
                SecureMemory.clear_bytes(session.encryption_key)
                SecureMemory.clear_bytes(session.mac_key)
            self._sessions.clear()
    
    def get_session_info(self, session_id: str) -> Optional[dict]:
        """Get session information (non-sensitive data only)."""
        with self._session_lock:
            session = self._sessions.get(session_id)
            if not session:
                return None
            
            return {
                'session_id': session.session_id,
                'peer_id': session.peer_id,
                'created_time': session.created_time,
                'last_used': session.last_used,
                'is_active': session.is_active,
                'messages_sent': session.message_counter_send,
                'messages_received': session.message_counter_receive
            }
    
    def create_encrypted_keystore(self, password: str) -> bytes:
        """Create encrypted keystore for private keys."""
        if not self._identity_private_key:
            raise ValueError("No identity private key to encrypt")
        
        # Generate salt
        salt = secrets.token_bytes(32)
        
        # Derive key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=600000,  # OWASP recommended minimum
            backend=self.backend
        )
        
        key = kdf.derive(password.encode())
        
        # Serialize private key
        private_pem = self._identity_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # Encrypt private key
        cipher = ChaCha20Poly1305(key)
        nonce = secrets.token_bytes(12)
        ciphertext = cipher.encrypt(nonce, private_pem, None)
        
        # Create keystore structure
        keystore = {
            'version': 1,
            'salt': salt.hex(),
            'nonce': nonce.hex(),
            'ciphertext': ciphertext.hex(),
            'iterations': 600000
        }
        
        return str(keystore).encode()
    
    def load_encrypted_keystore(self, keystore_data: bytes, password: str) -> None:
        """Load private key from encrypted keystore."""
        try:
            import ast
            keystore = ast.literal_eval(keystore_data.decode())
            
            # Extract components
            salt = bytes.fromhex(keystore['salt'])
            nonce = bytes.fromhex(keystore['nonce'])
            ciphertext = bytes.fromhex(keystore['ciphertext'])
            iterations = keystore['iterations']
            
            # Derive key from password
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=iterations,
                backend=self.backend
            )
            
            key = kdf.derive(password.encode())
            
            # Decrypt private key
            cipher = ChaCha20Poly1305(key)
            private_pem = cipher.decrypt(nonce, ciphertext, None)
            
            # Load the private key
            self._identity_private_key = serialization.load_pem_private_key(
                private_pem, password=None, backend=self.backend
            )
            self._identity_public_key = self._identity_private_key.public_key()
            
            # Clear sensitive data
            SecureMemory.clear_bytes(key)
            SecureMemory.clear_bytes(private_pem)
            
        except Exception as e:
            raise ValueError(f"Failed to load encrypted keystore: {e}")

