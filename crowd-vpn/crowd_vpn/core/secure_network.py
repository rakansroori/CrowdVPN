"""Production-ready secure network manager for Crowd VPN.

Implements:
- Proper peer authentication
- Input validation and sanitization
- Rate limiting and DoS protection
- Secure message protocol
- Connection management
- Access control
"""

import asyncio
import json
import logging
import time
import secrets
import socket
from typing import Dict, Set, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict, deque
from ipaddress import ip_address, AddressValueError

from ..crypto.secure_crypto import ProductionCryptoManager


class MessageType(Enum):
    """Secure message types."""
    HANDSHAKE_INIT = "handshake_init"
    HANDSHAKE_RESPONSE = "handshake_response"
    HANDSHAKE_COMPLETE = "handshake_complete"
    PEER_ANNOUNCEMENT = "peer_announcement"
    PEER_LIST_REQUEST = "peer_list_request"
    PEER_LIST_RESPONSE = "peer_list_response"
    FORWARD_PACKET = "forward_packet"
    HEARTBEAT = "heartbeat"
    ERROR = "error"


class PeerRole(Enum):
    """Peer roles for access control."""
    CLIENT = "client"
    RELAY = "relay"
    EXIT = "exit"
    HYBRID = "hybrid"
    BOOTSTRAP = "bootstrap"


@dataclass
class RateLimitBucket:
    """Token bucket for rate limiting."""
    capacity: int
    tokens: float
    last_refill: float
    refill_rate: float  # tokens per second


@dataclass
class PeerInfo:
    """Information about a connected peer."""
    peer_id: str
    ip_address: str
    port: int
    role: PeerRole
    public_key: bytes
    session_id: Optional[str] = None
    last_seen: float = field(default_factory=time.time)
    reputation_score: float = 0.5
    connection_time: float = field(default_factory=time.time)
    bytes_sent: int = 0
    bytes_received: int = 0
    messages_sent: int = 0
    messages_received: int = 0
    is_authenticated: bool = False
    rate_limit_bucket: RateLimitBucket = None


@dataclass
class SecureMessage:
    """Secure message structure."""
    message_type: MessageType
    sender_id: str
    recipient_id: str
    sequence: int
    timestamp: float
    payload: dict
    signature: Optional[bytes] = None
    session_id: Optional[str] = None


class InputValidator:
    """Input validation and sanitization."""
    
    MAX_MESSAGE_SIZE = 64 * 1024  # 64KB
    MAX_PEER_ID_LENGTH = 64
    MAX_IP_ADDRESS_LENGTH = 45  # IPv6
    MIN_PORT = 1024
    MAX_PORT = 65535
    MAX_PAYLOAD_SIZE = 32 * 1024  # 32KB
    
    @staticmethod
    def validate_peer_id(peer_id: str) -> bool:
        """Validate peer ID format."""
        if not isinstance(peer_id, str):
            return False
        if len(peer_id) > InputValidator.MAX_PEER_ID_LENGTH:
            return False
        # Check for valid hexadecimal characters only
        try:
            int(peer_id, 16)
            return True
        except ValueError:
            return False
    
    @staticmethod
    def validate_ip_address(ip_addr: str) -> bool:
        """Validate IP address format."""
        if not isinstance(ip_addr, str):
            return False
        if len(ip_addr) > InputValidator.MAX_IP_ADDRESS_LENGTH:
            return False
        try:
            ip_address(ip_addr)
            return True
        except (AddressValueError, ValueError):
            return False
    
    @staticmethod
    def validate_port(port: int) -> bool:
        """Validate port number."""
        return isinstance(port, int) and InputValidator.MIN_PORT <= port <= InputValidator.MAX_PORT
    
    @staticmethod
    def validate_message_size(data: bytes) -> bool:
        """Validate message size."""
        return len(data) <= InputValidator.MAX_MESSAGE_SIZE
    
    @staticmethod
    def sanitize_json_payload(payload: dict) -> dict:
        """Sanitize JSON payload."""
        # Remove dangerous keys and limit nesting
        def sanitize_recursive(obj, depth=0):
            if depth > 10:  # Prevent deep nesting
                return {}
            
            if isinstance(obj, dict):
                sanitized = {}
                for key, value in obj.items():
                    if isinstance(key, str) and len(key) <= 100:
                        sanitized[key] = sanitize_recursive(value, depth + 1)
                return sanitized
            elif isinstance(obj, list):
                return [sanitize_recursive(item, depth + 1) for item in obj[:100]]  # Limit list size
            elif isinstance(obj, (str, int, float, bool, type(None))):
                if isinstance(obj, str) and len(obj) > 1024:  # Limit string length
                    return obj[:1024]
                return obj
            else:
                return str(obj)[:100]  # Convert unknown types to limited strings
        
        return sanitize_recursive(payload)


class SecureNetworkManager:
    """Production-ready secure network manager."""
    
    # Security constants
    MAX_CONNECTIONS = 100
    HANDSHAKE_TIMEOUT = 30  # seconds
    HEARTBEAT_INTERVAL = 60  # seconds
    PEER_TIMEOUT = 300  # 5 minutes
    RATE_LIMIT_CAPACITY = 100  # tokens
    RATE_LIMIT_REFILL = 10  # tokens per second
    MAX_PENDING_HANDSHAKES = 20
    
    def __init__(self, listen_port: int = 8080, 
                 listen_host: str = "127.0.0.1",  # Secure default
                 role: PeerRole = PeerRole.HYBRID):
        self.listen_port = listen_port
        self.listen_host = listen_host
        self.role = role
        self.node_id = self._generate_secure_node_id()
        
        # Initialize crypto manager
        self.crypto_manager = ProductionCryptoManager()
        
        # Network state
        self.peers: Dict[str, PeerInfo] = {}
        self.connections: Dict[str, Tuple[asyncio.StreamReader, asyncio.StreamWriter]] = {}
        self.server: Optional[asyncio.Server] = None
        self.running = False
        
        # Security state
        self.pending_handshakes: Dict[str, float] = {}  # IP -> timestamp
        self.banned_ips: Set[str] = set()
        self.connection_counts: Dict[str, int] = defaultdict(int)  # IP -> count
        self.recent_connections: deque = deque(maxlen=1000)  # Recent connection attempts
        
        # Rate limiting
        self.rate_limits: Dict[str, RateLimitBucket] = {}  # peer_id -> bucket
        
        # Message tracking
        self.message_sequences: Dict[str, int] = {}  # peer_id -> last_sequence
        
        # Logging
        self.logger = logging.getLogger(__name__)
        self.security_logger = logging.getLogger(f"{__name__}.security")
        
        # Tasks
        self.maintenance_task: Optional[asyncio.Task] = None
        self.heartbeat_task: Optional[asyncio.Task] = None
    
    def _generate_secure_node_id(self) -> str:
        """Generate cryptographically secure node ID."""
        return secrets.token_hex(32)  # 256-bit secure random ID
    
    async def start(self) -> None:
        """Start the secure network manager."""
        if self.running:
            return
        
        self.running = True
        self.logger.info(f"Starting secure network manager on {self.listen_host}:{self.listen_port}")
        
        try:
            # Start server
            self.server = await asyncio.start_server(
                self._handle_connection,
                self.listen_host,  # Use specified host instead of 0.0.0.0
                self.listen_port
            )
            
            # Start maintenance tasks
            self.maintenance_task = asyncio.create_task(self._maintenance_loop())
            self.heartbeat_task = asyncio.create_task(self._heartbeat_loop())
            
            self.logger.info(f"Secure network manager started (Node ID: {self.node_id[:16]}...)")
            
            # Serve forever
            async with self.server:
                await self.server.serve_forever()
                
        except Exception as e:
            self.logger.error(f"Failed to start secure network manager: {e}")
            await self.stop()
            raise
    
    async def stop(self) -> None:
        """Stop the secure network manager."""
        if not self.running:
            return
        
        self.running = False
        self.logger.info("Stopping secure network manager")
        
        # Cancel tasks
        if self.maintenance_task:
            self.maintenance_task.cancel()
        if self.heartbeat_task:
            self.heartbeat_task.cancel()
        
        # Close server
        if self.server:
            self.server.close()
            await self.server.wait_closed()
        
        # Close all connections
        for peer_id, (reader, writer) in self.connections.items():
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
        
        # Clear state
        self.connections.clear()
        self.peers.clear()
        
        # Revoke all crypto sessions
        self.crypto_manager.revoke_all_sessions()
        
        self.logger.info("Secure network manager stopped")
    
    async def _handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        """Handle incoming connection with security checks."""
        client_ip = writer.get_extra_info('peername')[0]
        
        try:
            # Security checks
            if not await self._security_check(client_ip):
                writer.close()
                await writer.wait_closed()
                return
            
            # Track connection attempt
            self.recent_connections.append((client_ip, time.time()))
            self.connection_counts[client_ip] += 1
            
            # Perform secure handshake
            peer_id = await self._perform_secure_handshake(reader, writer, client_ip)
            if not peer_id:
                return
            
            # Store connection
            self.connections[peer_id] = (reader, writer)
            
            self.logger.info(f"Authenticated connection from peer {peer_id[:16]}... ({client_ip})")
            
            # Handle peer communication
            await self._handle_peer_communication(peer_id, reader, writer)
            
        except Exception as e:
            self.security_logger.warning(f"Connection handling error from {client_ip}: {e}")
        finally:
            # Cleanup
            if client_ip in self.connection_counts:
                self.connection_counts[client_ip] -= 1
                if self.connection_counts[client_ip] <= 0:
                    del self.connection_counts[client_ip]
            
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
    
    async def _security_check(self, client_ip: str) -> bool:
        """Perform security checks on incoming connection."""
        # Check if IP is banned
        if client_ip in self.banned_ips:
            self.security_logger.warning(f"Rejected connection from banned IP: {client_ip}")
            return False
        
        # Check connection count limit
        if len(self.connections) >= self.MAX_CONNECTIONS:
            self.security_logger.warning(f"Rejected connection from {client_ip}: max connections reached")
            return False
        
        # Check per-IP connection limit
        if self.connection_counts[client_ip] >= 5:  # Max 5 connections per IP
            self.security_logger.warning(f"Rejected connection from {client_ip}: per-IP limit exceeded")
            return False
        
        # Check pending handshakes limit
        if len(self.pending_handshakes) >= self.MAX_PENDING_HANDSHAKES:
            self.security_logger.warning(f"Rejected connection from {client_ip}: too many pending handshakes")
            return False
        
        # Check rate limiting (connection attempts)
        current_time = time.time()
        recent_from_ip = sum(1 for ip, timestamp in self.recent_connections 
                           if ip == client_ip and current_time - timestamp < 60)
        if recent_from_ip > 10:  # Max 10 connections per minute per IP
            self.security_logger.warning(f"Rejected connection from {client_ip}: rate limit exceeded")
            return False
        
        return True
    
    async def _perform_secure_handshake(self, reader: asyncio.StreamReader, 
                                       writer: asyncio.StreamWriter, client_ip: str) -> Optional[str]:
        """Perform secure three-way handshake."""
        try:
            # Add to pending handshakes
            self.pending_handshakes[client_ip] = time.time()
            
            # Wait for handshake init with timeout
            try:
                handshake_data = await asyncio.wait_for(
                    self._read_message(reader), 
                    timeout=self.HANDSHAKE_TIMEOUT
                )
            except asyncio.TimeoutError:
                self.security_logger.warning(f"Handshake timeout from {client_ip}")
                return None
            
            if not handshake_data or handshake_data.get('type') != MessageType.HANDSHAKE_INIT.value:
                self.security_logger.warning(f"Invalid handshake init from {client_ip}")
                return None
            
            # Validate handshake data
            peer_id = handshake_data.get('peer_id')
            peer_role = handshake_data.get('role')
            peer_ephemeral_key = handshake_data.get('ephemeral_key')
            peer_public_key = handshake_data.get('public_key')
            
            if not all([peer_id, peer_role, peer_ephemeral_key, peer_public_key]):
                self.security_logger.warning(f"Incomplete handshake data from {client_ip}")
                return None
            
            # Validate inputs
            if not InputValidator.validate_peer_id(peer_id):
                self.security_logger.warning(f"Invalid peer ID from {client_ip}")
                return None
            
            try:
                peer_role_enum = PeerRole(peer_role)
                peer_ephemeral_key_bytes = bytes.fromhex(peer_ephemeral_key)
                peer_public_key_bytes = bytes.fromhex(peer_public_key)
            except (ValueError, TypeError):
                self.security_logger.warning(f"Invalid handshake parameters from {client_ip}")
                return None
            
            # Establish secure session
            session_id = self.crypto_manager.establish_secure_session(
                peer_id, peer_ephemeral_key_bytes, peer_public_key_bytes
            )
            
            # Create peer info
            peer_info = PeerInfo(
                peer_id=peer_id,
                ip_address=client_ip,
                port=writer.get_extra_info('peername')[1],
                role=peer_role_enum,
                public_key=peer_public_key_bytes,
                session_id=session_id,
                rate_limit_bucket=RateLimitBucket(
                    capacity=self.RATE_LIMIT_CAPACITY,
                    tokens=self.RATE_LIMIT_CAPACITY,
                    last_refill=time.time(),
                    refill_rate=self.RATE_LIMIT_REFILL
                )
            )
            
            # Send handshake response
            response_data = {
                'type': MessageType.HANDSHAKE_RESPONSE.value,
                'peer_id': self.node_id,
                'role': self.role.value,
                'ephemeral_key': self.crypto_manager.get_ephemeral_public_key().hex(),
                'public_key': self.crypto_manager.get_identity_public_key().hex(),
                'session_id': session_id
            }
            
            # Sign the response
            response_json = json.dumps(response_data, sort_keys=True)
            signature = self.crypto_manager.sign_message(response_json.encode())
            response_data['signature'] = signature.hex()
            
            await self._write_message(writer, response_data)
            
            # Wait for handshake complete
            try:
                complete_data = await asyncio.wait_for(
                    self._read_message(reader),
                    timeout=self.HANDSHAKE_TIMEOUT
                )
            except asyncio.TimeoutError:
                self.security_logger.warning(f"Handshake complete timeout from {client_ip}")
                return None
            
            if (not complete_data or 
                complete_data.get('type') != MessageType.HANDSHAKE_COMPLETE.value or
                complete_data.get('session_id') != session_id):
                self.security_logger.warning(f"Invalid handshake complete from {client_ip}")
                return None
            
            # Verify signature
            complete_signature = bytes.fromhex(complete_data.get('signature', ''))
            complete_data_copy = complete_data.copy()
            del complete_data_copy['signature']
            complete_json = json.dumps(complete_data_copy, sort_keys=True)
            
            if not self.crypto_manager.verify_signature(
                complete_json.encode(), complete_signature, peer_public_key_bytes
            ):
                self.security_logger.warning(f"Invalid handshake signature from {client_ip}")
                return None
            
            # Handshake successful
            peer_info.is_authenticated = True
            self.peers[peer_id] = peer_info
            
            self.logger.info(f"Successful handshake with peer {peer_id[:16]}... ({client_ip})")
            
            return peer_id
            
        except Exception as e:
            self.security_logger.error(f"Handshake error with {client_ip}: {e}")
            return None
        finally:
            # Remove from pending handshakes
            self.pending_handshakes.pop(client_ip, None)
    
    async def _handle_peer_communication(self, peer_id: str, 
                                        reader: asyncio.StreamReader, 
                                        writer: asyncio.StreamWriter) -> None:
        """Handle authenticated peer communication."""
        peer_info = self.peers[peer_id]
        
        try:
            while self.running:
                # Read message with timeout
                try:
                    message_data = await asyncio.wait_for(
                        self._read_message(reader),
                        timeout=self.PEER_TIMEOUT
                    )
                except asyncio.TimeoutError:
                    self.logger.warning(f"Communication timeout with peer {peer_id[:16]}...")
                    break
                
                if not message_data:
                    break
                
                # Rate limiting
                if not self._check_rate_limit(peer_id):
                    self.security_logger.warning(f"Rate limit exceeded for peer {peer_id[:16]}...")
                    break
                
                # Process secure message
                await self._process_secure_message(peer_id, message_data, writer)
                
                # Update peer stats
                peer_info.last_seen = time.time()
                peer_info.messages_received += 1
                
        except Exception as e:
            self.logger.error(f"Peer communication error with {peer_id[:16]}...: {e}")
        finally:
            # Cleanup peer
            self._cleanup_peer(peer_id)
    
    async def _read_message(self, reader: asyncio.StreamReader) -> Optional[dict]:
        """Read and validate message from stream."""
        try:
            # Read message length (4 bytes)
            length_data = await reader.readexactly(4)
            message_length = int.from_bytes(length_data, 'big')
            
            # Validate message size
            if message_length > InputValidator.MAX_MESSAGE_SIZE:
                raise ValueError(f"Message too large: {message_length}")
            
            # Read message data
            message_data = await reader.readexactly(message_length)
            
            # Parse JSON
            message_dict = json.loads(message_data.decode('utf-8'))
            
            # Validate and sanitize
            message_dict = InputValidator.sanitize_json_payload(message_dict)
            
            return message_dict
            
        except Exception as e:
            self.logger.debug(f"Message read error: {e}")
            return None
    
    async def _write_message(self, writer: asyncio.StreamWriter, message: dict) -> None:
        """Write message to stream."""
        try:
            # Serialize message
            message_json = json.dumps(message).encode('utf-8')
            
            # Write length prefix
            length_bytes = len(message_json).to_bytes(4, 'big')
            writer.write(length_bytes)
            
            # Write message
            writer.write(message_json)
            await writer.drain()
            
        except Exception as e:
            self.logger.error(f"Message write error: {e}")
            raise
    
    def _check_rate_limit(self, peer_id: str) -> bool:
        """Check if peer is within rate limits."""
        peer_info = self.peers.get(peer_id)
        if not peer_info or not peer_info.rate_limit_bucket:
            return False
        
        bucket = peer_info.rate_limit_bucket
        current_time = time.time()
        
        # Refill tokens
        time_passed = current_time - bucket.last_refill
        bucket.tokens = min(
            bucket.capacity,
            bucket.tokens + time_passed * bucket.refill_rate
        )
        bucket.last_refill = current_time
        
        # Check if tokens available
        if bucket.tokens >= 1:
            bucket.tokens -= 1
            return True
        
        return False
    
    async def _process_secure_message(self, peer_id: str, message_data: dict, 
                                     writer: asyncio.StreamWriter) -> None:
        """Process secure message from authenticated peer."""
        try:
            message_type = message_data.get('type')
            
            if message_type == MessageType.HEARTBEAT.value:
                await self._handle_heartbeat(peer_id, message_data, writer)
            elif message_type == MessageType.PEER_LIST_REQUEST.value:
                await self._handle_peer_list_request(peer_id, message_data, writer)
            elif message_type == MessageType.PEER_ANNOUNCEMENT.value:
                await self._handle_peer_announcement(peer_id, message_data)
            elif message_type == MessageType.FORWARD_PACKET.value:
                await self._handle_forward_packet(peer_id, message_data)
            else:
                self.security_logger.warning(f"Unknown message type from peer {peer_id[:16]}...: {message_type}")
                
        except Exception as e:
            self.logger.error(f"Error processing message from peer {peer_id[:16]}...: {e}")
    
    async def _handle_heartbeat(self, peer_id: str, message_data: dict, 
                               writer: asyncio.StreamWriter) -> None:
        """Handle heartbeat message."""
        # Update last seen
        if peer_id in self.peers:
            self.peers[peer_id].last_seen = time.time()
        
        # Send heartbeat response
        response = {
            'type': MessageType.HEARTBEAT.value,
            'timestamp': time.time(),
            'peer_id': self.node_id
        }
        
        await self._write_message(writer, response)
    
    async def _handle_peer_list_request(self, peer_id: str, message_data: dict,
                                       writer: asyncio.StreamWriter) -> None:
        """Handle peer list request."""
        # Only provide peer list to authenticated relay/hybrid nodes
        peer_info = self.peers.get(peer_id)
        if not peer_info or peer_info.role not in [PeerRole.RELAY, PeerRole.HYBRID, PeerRole.BOOTSTRAP]:
            return
        
        # Prepare peer list (limited and anonymized)
        peer_list = []
        for p in list(self.peers.values())[:20]:  # Limit to 20 peers
            if p.peer_id != peer_id and p.is_authenticated:
                peer_list.append({
                    'peer_id': p.peer_id,
                    'role': p.role.value,
                    'reputation_score': p.reputation_score,
                    'last_seen': p.last_seen
                })
        
        response = {
            'type': MessageType.PEER_LIST_RESPONSE.value,
            'peers': peer_list,
            'timestamp': time.time()
        }
        
        await self._write_message(writer, response)
    
    async def _handle_peer_announcement(self, peer_id: str, message_data: dict) -> None:
        """Handle peer announcement."""
        # Validate and update peer information
        # This would include signature verification in production
        pass
    
    async def _handle_forward_packet(self, peer_id: str, message_data: dict) -> None:
        """Handle packet forwarding request."""
        # Implement secure packet forwarding
        # This would include authorization checks and traffic routing
        pass
    
    def _cleanup_peer(self, peer_id: str) -> None:
        """Clean up peer connection and data."""
        if peer_id in self.peers:
            peer_info = self.peers[peer_id]
            
            # Revoke crypto session
            if peer_info.session_id:
                self.crypto_manager.revoke_session(peer_info.session_id)
            
            # Remove peer
            del self.peers[peer_id]
        
        # Remove connection
        if peer_id in self.connections:
            del self.connections[peer_id]
        
        # Remove rate limit bucket
        if peer_id in self.rate_limits:
            del self.rate_limits[peer_id]
    
    async def _maintenance_loop(self) -> None:
        """Periodic maintenance tasks."""
        while self.running:
            try:
                current_time = time.time()
                
                # Clean up expired peers
                expired_peers = [
                    peer_id for peer_id, peer_info in self.peers.items()
                    if current_time - peer_info.last_seen > self.PEER_TIMEOUT
                ]
                
                for peer_id in expired_peers:
                    self.logger.info(f"Removing expired peer {peer_id[:16]}...")
                    self._cleanup_peer(peer_id)
                
                # Clean up expired handshakes
                expired_handshakes = [
                    ip for ip, timestamp in self.pending_handshakes.items()
                    if current_time - timestamp > self.HANDSHAKE_TIMEOUT
                ]
                
                for ip in expired_handshakes:
                    del self.pending_handshakes[ip]
                
                # Clean up crypto sessions
                self.crypto_manager._cleanup_expired_sessions()
                
                # Log statistics
                self.logger.info(
                    f"Network stats: {len(self.peers)} peers, "
                    f"{len(self.connections)} connections, "
                    f"{len(self.pending_handshakes)} pending handshakes"
                )
                
                await asyncio.sleep(60)  # Run every minute
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Maintenance loop error: {e}")
                await asyncio.sleep(10)
    
    async def _heartbeat_loop(self) -> None:
        """Send heartbeat messages to peers."""
        while self.running:
            try:
                # Send heartbeats to all connected peers
                for peer_id, (reader, writer) in list(self.connections.items()):
                    try:
                        heartbeat_msg = {
                            'type': MessageType.HEARTBEAT.value,
                            'timestamp': time.time(),
                            'peer_id': self.node_id
                        }
                        
                        await self._write_message(writer, heartbeat_msg)
                        
                    except Exception as e:
                        self.logger.warning(f"Failed to send heartbeat to {peer_id[:16]}...: {e}")
                        self._cleanup_peer(peer_id)
                
                await asyncio.sleep(self.HEARTBEAT_INTERVAL)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Heartbeat loop error: {e}")
                await asyncio.sleep(30)
    
    def get_network_stats(self) -> dict:
        """Get network statistics."""
        return {
            'node_id': self.node_id,
            'role': self.role.value,
            'total_peers': len(self.peers),
            'authenticated_peers': sum(1 for p in self.peers.values() if p.is_authenticated),
            'active_connections': len(self.connections),
            'pending_handshakes': len(self.pending_handshakes),
            'banned_ips': len(self.banned_ips),
            'bytes_sent': sum(p.bytes_sent for p in self.peers.values()),
            'bytes_received': sum(p.bytes_received for p in self.peers.values()),
            'messages_sent': sum(p.messages_sent for p in self.peers.values()),
            'messages_received': sum(p.messages_received for p in self.peers.values())
        }

