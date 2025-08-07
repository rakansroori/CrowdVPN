"""Encryption and cryptographic utilities for Crowd VPN."""

import os
import hashlib
import hmac
from typing import Tuple, Optional
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.backends import default_backend


class CryptoManager:
    """Manages cryptographic operations for the VPN."""
    
    def __init__(self):
        self.backend = default_backend()
        self.private_key: Optional[rsa.RSAPrivateKey] = None
        self.public_key: Optional[rsa.RSAPublicKey] = None
        self.session_keys: dict = {}  # peer_id -> session_key
        
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate RSA key pair for the node."""
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=self.backend
        )
        self.public_key = self.private_key.public_key()
        
        # Serialize keys
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return private_pem, public_pem
    
    def load_keypair(self, private_pem: bytes, public_pem: bytes):
        """Load existing key pair."""
        self.private_key = serialization.load_pem_private_key(
            private_pem, password=None, backend=self.backend
        )
        self.public_key = serialization.load_pem_public_key(
            public_pem, backend=self.backend
        )
    
    def get_public_key_hash(self) -> str:
        """Get hash of the public key for identification."""
        if not self.public_key:
            return ""
        
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        
        return hashlib.sha256(public_pem).hexdigest()[:16]
    
    def establish_session_key(self, peer_id: str, peer_public_key_pem: bytes) -> bytes:
        """Establish a shared session key with a peer using ECDH-like process."""
        # Load peer's public key
        peer_public_key = serialization.load_pem_public_key(
            peer_public_key_pem, backend=self.backend
        )
        
        # Generate a random session key
        session_key = os.urandom(32)  # 256-bit key
        
        # In a real implementation, you'd use proper key exchange (ECDH)
        # For now, we'll simulate with a deterministic key derivation
        combined_material = (
            self.get_public_key_hash().encode() +
            hashlib.sha256(peer_public_key_pem).hexdigest()[:16].encode()
        )
        
        # Derive session key using HKDF
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'crowd-vpn-session',
            backend=self.backend
        )
        
        derived_key = hkdf.derive(combined_material)
        self.session_keys[peer_id] = derived_key
        
        return derived_key
    
    def encrypt_data(self, data: bytes, peer_id: str) -> Tuple[bytes, bytes]:
        """Encrypt data for a specific peer using AES-GCM."""
        if peer_id not in self.session_keys:
            raise ValueError(f"No session key established for peer {peer_id}")
        
        session_key = self.session_keys[peer_id]
        
        # Generate random IV
        iv = os.urandom(12)  # 96-bit IV for GCM
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(session_key),
            modes.GCM(iv),
            backend=self.backend
        )
        
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Return IV + ciphertext + auth_tag
        return iv, ciphertext + encryptor.tag
    
    def decrypt_data(self, iv: bytes, encrypted_data: bytes, peer_id: str) -> bytes:
        """Decrypt data from a specific peer."""
        if peer_id not in self.session_keys:
            raise ValueError(f"No session key established for peer {peer_id}")
        
        session_key = self.session_keys[peer_id]
        
        # Split ciphertext and auth tag
        ciphertext = encrypted_data[:-16]  # All but last 16 bytes
        auth_tag = encrypted_data[-16:]    # Last 16 bytes
        
        # Create cipher
        cipher = Cipher(
            algorithms.AES(session_key),
            modes.GCM(iv, auth_tag),
            backend=self.backend
        )
        
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext
    
    def sign_data(self, data: bytes) -> bytes:
        """Sign data with our private key."""
        if not self.private_key:
            raise ValueError("No private key available for signing")
        
        signature = self.private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return signature
    
    def verify_signature(self, data: bytes, signature: bytes, peer_public_key_pem: bytes) -> bool:
        """Verify signature from a peer."""
        try:
            peer_public_key = serialization.load_pem_public_key(
                peer_public_key_pem, backend=self.backend
            )
            
            peer_public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
            
        except Exception:
            return False
    
    def encrypt_for_transport(self, data: bytes, peer_id: str) -> dict:
        """Encrypt data and prepare for network transport."""
        iv, encrypted_data = self.encrypt_data(data, peer_id)
        
        # Create transport packet
        packet = {
            'encrypted': True,
            'iv': iv.hex(),
            'data': encrypted_data.hex(),
            'sender': self.get_public_key_hash()
        }
        
        return packet
    
    def decrypt_from_transport(self, packet: dict, peer_id: str) -> bytes:
        """Decrypt data received from network transport."""
        if not packet.get('encrypted', False):
            raise ValueError("Packet is not encrypted")
        
        iv = bytes.fromhex(packet['iv'])
        encrypted_data = bytes.fromhex(packet['data'])
        
        return self.decrypt_data(iv, encrypted_data, peer_id)
    
    def generate_hmac(self, data: bytes, key: bytes) -> bytes:
        """Generate HMAC for data integrity."""
        h = hmac.new(key, data, hashlib.sha256)
        return h.digest()
    
    def verify_hmac(self, data: bytes, key: bytes, provided_hmac: bytes) -> bool:
        """Verify HMAC for data integrity."""
        expected_hmac = self.generate_hmac(data, key)
        return hmac.compare_digest(expected_hmac, provided_hmac)
    
    def derive_key_from_password(self, password: str, salt: bytes = None) -> bytes:
        """Derive a key from a password using PBKDF2."""
        if salt is None:
            salt = os.urandom(16)
        
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=self.backend
        )
        
        key = kdf.derive(password.encode())
        return key
    
    def secure_random_bytes(self, length: int) -> bytes:
        """Generate cryptographically secure random bytes."""
        return os.urandom(length)
    
    def hash_data(self, data: bytes) -> str:
        """Hash data using SHA-256."""
        return hashlib.sha256(data).hexdigest()

