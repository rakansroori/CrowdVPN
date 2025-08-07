"""Secure configuration management for Crowd VPN.

Provides:
- Configuration validation and sanitization
- Secure default settings
- Environment variable support
- Configuration encryption
- Security policy enforcement
"""

import os
import yaml
import secrets
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from pathlib import Path
import logging

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend


@dataclass
class SecurityPolicy:
    """Security policy configuration."""
    max_connections: int = 50
    rate_limit_requests_per_minute: int = 600  # 10 per second
    handshake_timeout_seconds: int = 30
    session_timeout_seconds: int = 3600  # 1 hour
    key_rotation_interval_seconds: int = 1800  # 30 minutes
    max_message_size_kb: int = 64
    max_peer_connections_per_ip: int = 3
    ban_duration_seconds: int = 3600  # 1 hour
    reputation_threshold: float = 0.3
    require_authentication: bool = True
    enable_rate_limiting: bool = True
    enable_intrusion_detection: bool = True
    log_security_events: bool = True
    secure_logging: bool = True


@dataclass
class NetworkConfig:
    """Network configuration."""
    listen_host: str = "127.0.0.1"  # Secure default - localhost only
    listen_port: int = 8080
    external_host: Optional[str] = None  # Auto-detected if None
    bootstrap_nodes: List[str] = field(default_factory=list)
    enable_upnp: bool = False  # Disabled for security
    enable_local_discovery: bool = False  # Disabled for security
    bind_interface: Optional[str] = None
    ipv6_enabled: bool = False
    tcp_keepalive: bool = True
    tcp_nodelay: bool = True
    connection_timeout: int = 30
    read_timeout: int = 60
    write_timeout: int = 30


@dataclass
class CryptoConfig:
    """Cryptographic configuration."""
    key_size: int = 256  # Ed25519/X25519
    session_key_size: int = 256
    pbkdf2_iterations: int = 600000  # OWASP 2023 minimum
    enable_perfect_forward_secrecy: bool = True
    require_key_authentication: bool = True
    key_rotation_enabled: bool = True
    secure_random_enabled: bool = True
    constant_time_operations: bool = True
    memory_protection_enabled: bool = True


@dataclass
class LoggingConfig:
    """Logging configuration."""
    level: str = "INFO"
    console_enabled: bool = True
    file_enabled: bool = True
    file_path: str = "crowd_vpn.log"
    security_file_path: str = "crowd_vpn_security.log"
    max_file_size_mb: int = 100
    backup_count: int = 5
    format_string: str = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    sensitive_data_filtering: bool = True
    log_rotation_enabled: bool = True
    syslog_enabled: bool = False
    syslog_address: str = "localhost"
    syslog_port: int = 514


@dataclass 
class MonitoringConfig:
    """Monitoring and alerting configuration."""
    metrics_enabled: bool = True
    metrics_interval_seconds: int = 60
    alerting_enabled: bool = True
    alert_thresholds: Dict[str, Any] = field(default_factory=lambda: {
        'high_cpu_percent': 80,
        'high_memory_percent': 80,
        'high_connection_count': 90,
        'failed_authentication_rate': 10,  # per minute
        'suspicious_activity_score': 0.7
    })
    performance_tracking: bool = True
    security_monitoring: bool = True


class SecureConfigManager:
    """Secure configuration manager with validation and encryption."""
    
    DEFAULT_CONFIG_PATH = "config/secure_config.yaml"
    ENCRYPTED_CONFIG_SUFFIX = ".encrypted"
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or self.DEFAULT_CONFIG_PATH
        self.logger = logging.getLogger(__name__)
        
        # Configuration sections
        self.security_policy = SecurityPolicy()
        self.network = NetworkConfig()
        self.crypto = CryptoConfig()
        self.logging = LoggingConfig()
        self.monitoring = MonitoringConfig()
        
        # Runtime state
        self._config_hash: Optional[str] = None
        self._is_encrypted = False
    
    def load_config(self, password: Optional[str] = None) -> None:
        """Load configuration from file with optional encryption."""
        try:
            config_file = Path(self.config_path)
            encrypted_file = Path(f"{self.config_path}{self.ENCRYPTED_CONFIG_SUFFIX}")
            
            # Check if encrypted config exists
            if encrypted_file.exists():
                if not password:
                    raise ValueError("Password required for encrypted configuration")
                config_data = self._load_encrypted_config(encrypted_file, password)
                self._is_encrypted = True
            elif config_file.exists():
                config_data = self._load_plain_config(config_file)
                self._is_encrypted = False
            else:
                # Use default configuration
                self.logger.info("No configuration file found, using secure defaults")
                return
            
            # Apply configuration
            self._apply_config_data(config_data)
            
            # Validate configuration
            self._validate_configuration()
            
            # Apply environment variable overrides
            self._apply_environment_overrides()
            
            # Calculate config hash for integrity checking
            self._config_hash = self._calculate_config_hash()
            
            self.logger.info(f"Configuration loaded successfully from {self.config_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to load configuration: {e}")
            raise
    
    def save_config(self, password: Optional[str] = None, encrypt: bool = False) -> None:
        """Save configuration to file with optional encryption."""
        try:
            config_data = self._serialize_config()
            
            if encrypt or self._is_encrypted:
                if not password:
                    raise ValueError("Password required for encrypted configuration")
                encrypted_file = Path(f"{self.config_path}{self.ENCRYPTED_CONFIG_SUFFIX}")
                self._save_encrypted_config(encrypted_file, config_data, password)
                self._is_encrypted = True
            else:
                config_file = Path(self.config_path)
                self._save_plain_config(config_file, config_data)
            
            # Update config hash
            self._config_hash = self._calculate_config_hash()
            
            self.logger.info(f"Configuration saved successfully to {self.config_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
            raise
    
    def _load_plain_config(self, config_file: Path) -> Dict[str, Any]:
        """Load plain YAML configuration file."""
        with open(config_file, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
        
        if not isinstance(config_data, dict):
            raise ValueError("Configuration file must contain a dictionary")
        
        return config_data
    
    def _save_plain_config(self, config_file: Path, config_data: Dict[str, Any]) -> None:
        """Save plain YAML configuration file."""
        # Ensure directory exists
        config_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(config_file, 'w', encoding='utf-8') as f:
            yaml.safe_dump(config_data, f, default_flow_style=False, sort_keys=True)
        
        # Set secure file permissions (readable only by owner)
        os.chmod(config_file, 0o600)
    
    def _load_encrypted_config(self, encrypted_file: Path, password: str) -> Dict[str, Any]:
        """Load encrypted configuration file."""
        with open(encrypted_file, 'rb') as f:
            encrypted_data = f.read()
        
        # Parse encrypted structure
        import json
        try:
            encrypted_structure = json.loads(encrypted_data.decode('utf-8'))
        except (json.JSONDecodeError, UnicodeDecodeError):
            raise ValueError("Invalid encrypted configuration file format")
        
        # Extract components
        salt = bytes.fromhex(encrypted_structure['salt'])
        nonce = bytes.fromhex(encrypted_structure['nonce'])
        ciphertext = bytes.fromhex(encrypted_structure['ciphertext'])
        iterations = encrypted_structure['iterations']
        
        # Derive key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        # Decrypt configuration
        cipher = ChaCha20Poly1305(key)
        try:
            decrypted_yaml = cipher.decrypt(nonce, ciphertext, None)
            config_data = yaml.safe_load(decrypted_yaml.decode('utf-8'))
        except Exception:
            raise ValueError("Failed to decrypt configuration (wrong password?)")
        
        if not isinstance(config_data, dict):
            raise ValueError("Decrypted configuration must contain a dictionary")
        
        return config_data
    
    def _save_encrypted_config(self, encrypted_file: Path, 
                              config_data: Dict[str, Any], password: str) -> None:
        """Save encrypted configuration file."""
        # Ensure directory exists
        encrypted_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Serialize configuration to YAML
        config_yaml = yaml.safe_dump(config_data, default_flow_style=False, sort_keys=True)
        
        # Generate encryption parameters
        salt = secrets.token_bytes(32)
        nonce = secrets.token_bytes(12)
        iterations = 600000
        
        # Derive key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend()
        )
        key = kdf.derive(password.encode())
        
        # Encrypt configuration
        cipher = ChaCha20Poly1305(key)
        ciphertext = cipher.encrypt(nonce, config_yaml.encode('utf-8'), None)
        
        # Create encrypted structure
        encrypted_structure = {
            'version': 1,
            'algorithm': 'ChaCha20Poly1305',
            'kdf': 'PBKDF2-SHA256',
            'iterations': iterations,
            'salt': salt.hex(),
            'nonce': nonce.hex(),
            'ciphertext': ciphertext.hex()
        }
        
        # Save encrypted file
        import json
        with open(encrypted_file, 'w', encoding='utf-8') as f:
            json.dump(encrypted_structure, f, indent=2)
        
        # Set secure file permissions
        os.chmod(encrypted_file, 0o600)
    
    def _apply_config_data(self, config_data: Dict[str, Any]) -> None:
        """Apply configuration data to internal structures."""
        # Security policy
        if 'security_policy' in config_data:
            security_data = config_data['security_policy']
            for key, value in security_data.items():
                if hasattr(self.security_policy, key):
                    setattr(self.security_policy, key, value)
        
        # Network configuration
        if 'network' in config_data:
            network_data = config_data['network']
            for key, value in network_data.items():
                if hasattr(self.network, key):
                    setattr(self.network, key, value)
        
        # Crypto configuration
        if 'crypto' in config_data:
            crypto_data = config_data['crypto']
            for key, value in crypto_data.items():
                if hasattr(self.crypto, key):
                    setattr(self.crypto, key, value)
        
        # Logging configuration
        if 'logging' in config_data:
            logging_data = config_data['logging']
            for key, value in logging_data.items():
                if hasattr(self.logging, key):
                    setattr(self.logging, key, value)
        
        # Monitoring configuration
        if 'monitoring' in config_data:
            monitoring_data = config_data['monitoring']
            for key, value in monitoring_data.items():
                if hasattr(self.monitoring, key):
                    setattr(self.monitoring, key, value)
    
    def _serialize_config(self) -> Dict[str, Any]:
        """Serialize configuration to dictionary."""
        return {
            'security_policy': {
                'max_connections': self.security_policy.max_connections,
                'rate_limit_requests_per_minute': self.security_policy.rate_limit_requests_per_minute,
                'handshake_timeout_seconds': self.security_policy.handshake_timeout_seconds,
                'session_timeout_seconds': self.security_policy.session_timeout_seconds,
                'key_rotation_interval_seconds': self.security_policy.key_rotation_interval_seconds,
                'max_message_size_kb': self.security_policy.max_message_size_kb,
                'max_peer_connections_per_ip': self.security_policy.max_peer_connections_per_ip,
                'ban_duration_seconds': self.security_policy.ban_duration_seconds,
                'reputation_threshold': self.security_policy.reputation_threshold,
                'require_authentication': self.security_policy.require_authentication,
                'enable_rate_limiting': self.security_policy.enable_rate_limiting,
                'enable_intrusion_detection': self.security_policy.enable_intrusion_detection,
                'log_security_events': self.security_policy.log_security_events,
                'secure_logging': self.security_policy.secure_logging
            },
            'network': {
                'listen_host': self.network.listen_host,
                'listen_port': self.network.listen_port,
                'external_host': self.network.external_host,
                'bootstrap_nodes': self.network.bootstrap_nodes,
                'enable_upnp': self.network.enable_upnp,
                'enable_local_discovery': self.network.enable_local_discovery,
                'bind_interface': self.network.bind_interface,
                'ipv6_enabled': self.network.ipv6_enabled,
                'tcp_keepalive': self.network.tcp_keepalive,
                'tcp_nodelay': self.network.tcp_nodelay,
                'connection_timeout': self.network.connection_timeout,
                'read_timeout': self.network.read_timeout,
                'write_timeout': self.network.write_timeout
            },
            'crypto': {
                'key_size': self.crypto.key_size,
                'session_key_size': self.crypto.session_key_size,
                'pbkdf2_iterations': self.crypto.pbkdf2_iterations,
                'enable_perfect_forward_secrecy': self.crypto.enable_perfect_forward_secrecy,
                'require_key_authentication': self.crypto.require_key_authentication,
                'key_rotation_enabled': self.crypto.key_rotation_enabled,
                'secure_random_enabled': self.crypto.secure_random_enabled,
                'constant_time_operations': self.crypto.constant_time_operations,
                'memory_protection_enabled': self.crypto.memory_protection_enabled
            },
            'logging': {
                'level': self.logging.level,
                'console_enabled': self.logging.console_enabled,
                'file_enabled': self.logging.file_enabled,
                'file_path': self.logging.file_path,
                'security_file_path': self.logging.security_file_path,
                'max_file_size_mb': self.logging.max_file_size_mb,
                'backup_count': self.logging.backup_count,
                'format_string': self.logging.format_string,
                'sensitive_data_filtering': self.logging.sensitive_data_filtering,
                'log_rotation_enabled': self.logging.log_rotation_enabled,
                'syslog_enabled': self.logging.syslog_enabled,
                'syslog_address': self.logging.syslog_address,
                'syslog_port': self.logging.syslog_port
            },
            'monitoring': {
                'metrics_enabled': self.monitoring.metrics_enabled,
                'metrics_interval_seconds': self.monitoring.metrics_interval_seconds,
                'alerting_enabled': self.monitoring.alerting_enabled,
                'alert_thresholds': self.monitoring.alert_thresholds,
                'performance_tracking': self.monitoring.performance_tracking,
                'security_monitoring': self.monitoring.security_monitoring
            }
        }
    
    def _validate_configuration(self) -> None:
        """Validate configuration for security and correctness."""
        errors = []
        warnings = []
        
        # Security policy validation
        if self.security_policy.max_connections > 1000:
            warnings.append("High max_connections may impact performance")
        
        if self.security_policy.handshake_timeout_seconds > 120:
            warnings.append("Long handshake timeout may enable DoS attacks")
        
        if self.security_policy.reputation_threshold < 0.1:
            warnings.append("Low reputation threshold may allow malicious peers")
        
        # Network validation
        if self.network.listen_host == "0.0.0.0":
            warnings.append("Binding to 0.0.0.0 exposes service to all interfaces")
        
        if self.network.listen_port < 1024:
            errors.append("Privileged port numbers require root access")
        
        if self.network.enable_upnp:
            warnings.append("UPnP may create security vulnerabilities")
        
        # Crypto validation
        if self.crypto.pbkdf2_iterations < 100000:
            errors.append("PBKDF2 iterations too low (minimum 100,000)")
        
        if not self.crypto.enable_perfect_forward_secrecy:
            warnings.append("Perfect Forward Secrecy disabled reduces security")
        
        # Logging validation
        log_level = self.logging.level.upper()
        if log_level not in ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']:
            errors.append(f"Invalid log level: {self.logging.level}")
        
        if log_level == 'DEBUG':
            warnings.append("DEBUG logging may expose sensitive information")
        
        # Report validation results
        if errors:
            raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")
        
        if warnings:
            for warning in warnings:
                self.logger.warning(f"Configuration warning: {warning}")
    
    def _apply_environment_overrides(self) -> None:
        """Apply environment variable overrides."""
        # Network overrides
        if 'CROWD_VPN_LISTEN_HOST' in os.environ:
            self.network.listen_host = os.environ['CROWD_VPN_LISTEN_HOST']
        
        if 'CROWD_VPN_LISTEN_PORT' in os.environ:
            try:
                self.network.listen_port = int(os.environ['CROWD_VPN_LISTEN_PORT'])
            except ValueError:
                self.logger.warning("Invalid CROWD_VPN_LISTEN_PORT environment variable")
        
        # Security overrides
        if 'CROWD_VPN_MAX_CONNECTIONS' in os.environ:
            try:
                self.security_policy.max_connections = int(os.environ['CROWD_VPN_MAX_CONNECTIONS'])
            except ValueError:
                self.logger.warning("Invalid CROWD_VPN_MAX_CONNECTIONS environment variable")
        
        # Logging overrides
        if 'CROWD_VPN_LOG_LEVEL' in os.environ:
            self.logging.level = os.environ['CROWD_VPN_LOG_LEVEL']
        
        if 'CROWD_VPN_LOG_FILE' in os.environ:
            self.logging.file_path = os.environ['CROWD_VPN_LOG_FILE']
    
    def _calculate_config_hash(self) -> str:
        """Calculate hash of current configuration for integrity checking."""
        import hashlib
        config_data = self._serialize_config()
        config_str = str(sorted(config_data.items()))
        return hashlib.sha256(config_str.encode()).hexdigest()
    
    def verify_integrity(self) -> bool:
        """Verify configuration integrity hasn't changed."""
        if not self._config_hash:
            return True  # No baseline to compare against
        
        current_hash = self._calculate_config_hash()
        return current_hash == self._config_hash
    
    def generate_default_config(self) -> Dict[str, Any]:
        """Generate secure default configuration."""
        return self._serialize_config()
    
    def get_security_recommendations(self) -> List[str]:
        """Get security recommendations based on current configuration."""
        recommendations = []
        
        if self.network.listen_host == "0.0.0.0":
            recommendations.append("Consider binding to specific interface instead of 0.0.0.0")
        
        if not self.security_policy.require_authentication:
            recommendations.append("Enable authentication for better security")
        
        if not self.security_policy.enable_rate_limiting:
            recommendations.append("Enable rate limiting to prevent DoS attacks")
        
        if self.crypto.pbkdf2_iterations < 600000:
            recommendations.append("Increase PBKDF2 iterations to 600,000+ for better security")
        
        if not self.logging.sensitive_data_filtering:
            recommendations.append("Enable sensitive data filtering in logs")
        
        if not self._is_encrypted:
            recommendations.append("Consider encrypting configuration file")
        
        return recommendations

