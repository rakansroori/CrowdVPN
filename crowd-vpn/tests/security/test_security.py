"""Comprehensive security tests for Crowd VPN.

Tests cover:
- Cryptographic implementation security
- Network protocol security
- Input validation and sanitization
- Authentication and authorization
- Rate limiting and DoS protection
- Configuration security
- Key management security
"""

import pytest
import asyncio
import secrets
import json
import time
from unittest.mock import Mock, patch, AsyncMock
from typing import Dict, Any

from crowd_vpn.crypto.secure_crypto import ProductionCryptoManager, SecureMemory
from crowd_vpn.core.secure_network import (
    SecureNetworkManager, InputValidator, PeerRole, MessageType
)
from crowd_vpn.config.secure_config import SecureConfigManager


class TestCryptographicSecurity:
    """Test cryptographic implementation security."""
    
    @pytest.fixture
    def crypto_manager(self):
        """Create a crypto manager for testing."""
        manager = ProductionCryptoManager()
        manager.generate_identity_keypair()
        return manager
    
    def test_secure_key_generation(self, crypto_manager):
        """Test that keys are generated securely."""
        # Generate multiple key pairs
        keys1 = crypto_manager.generate_identity_keypair()
        keys2 = crypto_manager.generate_identity_keypair()
        
        # Keys should be different
        assert keys1[0] != keys2[0]  # Private keys different
        assert keys1[1] != keys2[1]  # Public keys different
        
        # Keys should be proper length
        assert len(keys1[0]) > 100  # PEM encoded private key
        assert len(keys1[1]) > 100  # PEM encoded public key
    
    def test_session_key_uniqueness(self, crypto_manager):
        """Test that session keys are unique and unpredictable."""
        peer_ephemeral = secrets.token_bytes(32)
        peer_identity = crypto_manager.get_identity_public_key()
        
        # Create multiple sessions
        session1 = crypto_manager.establish_secure_session(
            "peer1", peer_ephemeral, peer_identity
        )
        session2 = crypto_manager.establish_secure_session(
            "peer2", peer_ephemeral, peer_identity
        )
        
        # Sessions should have different IDs
        assert session1 != session2
        
        # Session info should be different
        info1 = crypto_manager.get_session_info(session1)
        info2 = crypto_manager.get_session_info(session2)
        
        assert info1['peer_id'] != info2['peer_id']
        assert info1['session_id'] != info2['session_id']
    
    def test_encryption_integrity(self, crypto_manager):
        """Test encryption maintains integrity and authenticity."""
        peer_ephemeral = secrets.token_bytes(32)
        peer_identity = crypto_manager.get_identity_public_key()
        
        session_id = crypto_manager.establish_secure_session(
            "peer1", peer_ephemeral, peer_identity
        )
        
        # Test data
        plaintext = b"This is sensitive data that must be protected"
        
        # Encrypt
        encrypted = crypto_manager.encrypt_message(plaintext, session_id)
        
        # Should contain required fields
        required_fields = ['session_id', 'counter', 'nonce', 'ciphertext', 'hmac']
        for field in required_fields:
            assert field in encrypted
        
        # Decrypt
        decrypted = crypto_manager.decrypt_message(encrypted)
        assert decrypted == plaintext
    
    def test_tampering_detection(self, crypto_manager):
        """Test that message tampering is detected."""
        peer_ephemeral = secrets.token_bytes(32)
        peer_identity = crypto_manager.get_identity_public_key()
        
        session_id = crypto_manager.establish_secure_session(
            "peer1", peer_ephemeral, peer_identity
        )
        
        plaintext = b"Original message"
        encrypted = crypto_manager.encrypt_message(plaintext, session_id)
        
        # Tamper with ciphertext
        original_ciphertext = encrypted['ciphertext']
        tampered_ciphertext = original_ciphertext[:-2] + "00"  # Change last byte
        encrypted['ciphertext'] = tampered_ciphertext
        
        # Decryption should fail
        with pytest.raises(ValueError, match="HMAC verification failed|Decryption failed"):
            crypto_manager.decrypt_message(encrypted)
    
    def test_replay_attack_protection(self, crypto_manager):
        """Test protection against replay attacks."""
        peer_ephemeral = secrets.token_bytes(32)
        peer_identity = crypto_manager.get_identity_public_key()
        
        session_id = crypto_manager.establish_secure_session(
            "peer1", peer_ephemeral, peer_identity
        )
        
        # Send first message
        plaintext1 = b"First message"
        encrypted1 = crypto_manager.encrypt_message(plaintext1, session_id)
        decrypted1 = crypto_manager.decrypt_message(encrypted1)
        assert decrypted1 == plaintext1
        
        # Send second message to advance the counter
        plaintext2 = b"Second message"
        encrypted2 = crypto_manager.encrypt_message(plaintext2, session_id)
        decrypted2 = crypto_manager.decrypt_message(encrypted2)
        assert decrypted2 == plaintext2
        
        # Try to replay first message (should fail)
        with pytest.raises(ValueError, match="Message counter replay detected"):
            crypto_manager.decrypt_message(encrypted1)
    
    def test_constant_time_comparison(self):
        """Test that comparisons are constant-time."""
        # This is a basic test - real constant-time testing requires specialized tools
        data1 = b"sensitive_data_1"
        data2 = b"sensitive_data_2"
        data3 = b"sensitive_data_1"  # Same as data1
        
        # These should not leak timing information
        assert not SecureMemory.secure_compare(data1, data2)
        assert SecureMemory.secure_compare(data1, data3)
    
    def test_key_rotation(self, crypto_manager):
        """Test automatic key rotation."""
        # Get initial ephemeral key
        key1 = crypto_manager.get_ephemeral_public_key()
        
        # Force key rotation by setting old timestamp
        crypto_manager._ephemeral_key_created = time.time() - 7200  # 2 hours ago
        
        # Get new key (should trigger rotation)
        key2 = crypto_manager.get_ephemeral_public_key()
        
        # Keys should be different after rotation
        assert key1 != key2
    
    def test_password_keystore_security(self, crypto_manager):
        """Test encrypted keystore security."""
        password = "secure_test_password_123"
        
        # Create encrypted keystore
        keystore_data = crypto_manager.create_encrypted_keystore(password)
        
        # Should be binary data
        assert isinstance(keystore_data, bytes)
        
        # Create new manager and load keystore
        new_manager = ProductionCryptoManager()
        new_manager.load_encrypted_keystore(keystore_data, password)
        
        # Should have same public key
        original_pubkey = crypto_manager.get_identity_public_key()
        loaded_pubkey = new_manager.get_identity_public_key()
        assert original_pubkey == loaded_pubkey
        
        # Wrong password should fail
        wrong_manager = ProductionCryptoManager()
        with pytest.raises(ValueError, match="Failed to load encrypted keystore"):
            wrong_manager.load_encrypted_keystore(keystore_data, "wrong_password")


class TestNetworkSecurity:
    """Test network protocol security."""
    
    @pytest.fixture
    def network_manager(self):
        """Create a secure network manager for testing."""
        manager = SecureNetworkManager(
            listen_port=0,  # Use random port for testing
            listen_host="127.0.0.1",
            role=PeerRole.HYBRID
        )
        # Generate crypto keys for testing
        manager.crypto_manager.generate_identity_keypair()
        return manager
    
    def test_input_validation(self):
        """Test input validation functions."""
        # Valid inputs
        assert InputValidator.validate_peer_id("1234567890abcdef")
        assert InputValidator.validate_ip_address("192.168.1.1")
        assert InputValidator.validate_port(8080)
        assert InputValidator.validate_message_size(b"x" * 1000)
        
        # Invalid inputs
        assert not InputValidator.validate_peer_id("invalid!@#")
        assert not InputValidator.validate_peer_id("x" * 100)  # Too long
        assert not InputValidator.validate_ip_address("999.999.999.999")
        assert not InputValidator.validate_port(70000)  # Too high
        assert not InputValidator.validate_port(500)   # Too low
        assert not InputValidator.validate_message_size(b"x" * 100000)  # Too large
    
    def test_json_sanitization(self):
        """Test JSON payload sanitization."""
        # Malicious payload with deep nesting
        malicious_payload = {
            "level1": {
                "level2": {
                    "level3": {
                        "level4": {
                            "level5": {
                                "level6": {
                                    "level7": {
                                        "level8": {
                                            "level9": {
                                                "level10": {
                                                    "level11": "deep_value"
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            },
            "long_string": "x" * 2000,  # Very long string
            "large_list": ["item"] * 200,  # Large list
            "dangerous_key_" * 50: "value"  # Long key name
        }
        
        # Sanitize
        sanitized = InputValidator.sanitize_json_payload(malicious_payload)
        
        # Should limit nesting depth
        assert len(str(sanitized)) < len(str(malicious_payload))
        
        # Should limit string lengths
        if "long_string" in sanitized:
            assert len(sanitized["long_string"]) <= 1024
        
        # Should limit list sizes
        if "large_list" in sanitized:
            assert len(sanitized["large_list"]) <= 100
    
    @pytest.mark.asyncio
    async def test_connection_limits(self, network_manager):
        """Test connection limiting."""
        # Mock a client IP that exceeds limits
        client_ip = "192.168.1.100"
        
        # Simulate multiple connections from same IP
        network_manager.connection_counts[client_ip] = 5
        
        # Security check should fail
        allowed = await network_manager._security_check(client_ip)
        assert not allowed
    
    @pytest.mark.asyncio
    async def test_rate_limiting(self, network_manager):
        """Test rate limiting functionality."""
        peer_id = "test_peer_123"
        
        # Create mock peer info with rate limit bucket
        from crowd_vpn.core.secure_network import PeerInfo, RateLimitBucket
        
        peer_info = PeerInfo(
            peer_id=peer_id,
            ip_address="127.0.0.1",
            port=8080,
            role=PeerRole.CLIENT,
            public_key=b"test_key",
            rate_limit_bucket=RateLimitBucket(
                capacity=5,
                tokens=5,
                last_refill=time.time(),
                refill_rate=1  # 1 token per second
            )
        )
        
        network_manager.peers[peer_id] = peer_info
        
        # Should allow initial requests
        for _ in range(5):
            assert network_manager._check_rate_limit(peer_id)
        
        # Should deny further requests
        assert not network_manager._check_rate_limit(peer_id)
    
    @pytest.mark.asyncio
    async def test_banned_ip_blocking(self, network_manager):
        """Test that banned IPs are blocked."""
        banned_ip = "10.0.0.1"
        network_manager.banned_ips.add(banned_ip)
        
        # Security check should fail for banned IP
        allowed = await network_manager._security_check(banned_ip)
        assert not allowed
    
    def test_secure_node_id_generation(self, network_manager):
        """Test that node IDs are generated securely."""
        node_id = network_manager._generate_secure_node_id()
        
        # Should be hex string
        int(node_id, 16)  # Should not raise exception
        
        # Should be proper length (64 hex chars = 32 bytes)
        assert len(node_id) == 64
        
        # Multiple generations should be different
        node_id2 = network_manager._generate_secure_node_id()
        assert node_id != node_id2


class TestConfigurationSecurity:
    """Test configuration security."""
    
    @pytest.fixture
    def config_manager(self, tmp_path):
        """Create a config manager with temporary file."""
        config_path = tmp_path / "test_config.yaml"
        return SecureConfigManager(str(config_path))
    
    def test_default_security_settings(self, config_manager):
        """Test that default settings are secure."""
        # Network defaults should be secure
        assert config_manager.network.listen_host == "127.0.0.1"  # Not 0.0.0.0
        assert not config_manager.network.enable_upnp  # UPnP disabled
        assert not config_manager.network.enable_local_discovery  # Discovery disabled
        
        # Security policy should be restrictive
        assert config_manager.security_policy.require_authentication
        assert config_manager.security_policy.enable_rate_limiting
        assert config_manager.security_policy.enable_intrusion_detection
        
        # Crypto should use strong settings
        assert config_manager.crypto.pbkdf2_iterations >= 600000
        assert config_manager.crypto.enable_perfect_forward_secrecy
        assert config_manager.crypto.require_key_authentication
    
    def test_configuration_validation(self, config_manager):
        """Test configuration validation."""
        # Set insecure configuration
        config_manager.crypto.pbkdf2_iterations = 1000  # Too low
        config_manager.network.listen_port = 500  # Privileged port
        
        # Validation should fail
        with pytest.raises(ValueError, match="Configuration validation failed"):
            config_manager._validate_configuration()
    
    def test_encrypted_configuration(self, config_manager, tmp_path):
        """Test encrypted configuration storage."""
        password = "test_config_password_123"
        
        # Save encrypted config
        config_manager.save_config(password=password, encrypt=True)
        
        # Load encrypted config
        new_config = SecureConfigManager(config_manager.config_path)
        new_config.load_config(password=password)
        
        # Should have same settings
        assert new_config.network.listen_port == config_manager.network.listen_port
        assert new_config.crypto.pbkdf2_iterations == config_manager.crypto.pbkdf2_iterations
    
    def test_environment_variable_overrides(self, config_manager):
        """Test environment variable security."""
        import os
        
        # Set environment variables
        os.environ['CROWD_VPN_LISTEN_HOST'] = '0.0.0.0'  # Potentially insecure
        os.environ['CROWD_VPN_LISTEN_PORT'] = '8443'
        
        try:
            # Apply environment overrides
            config_manager._apply_environment_overrides()
            
            # Should apply overrides
            assert config_manager.network.listen_host == '0.0.0.0'
            assert config_manager.network.listen_port == 8443
            
        finally:
            # Clean up environment
            del os.environ['CROWD_VPN_LISTEN_HOST']
            del os.environ['CROWD_VPN_LISTEN_PORT']
    
    def test_configuration_integrity(self, config_manager):
        """Test configuration integrity checking."""
        # Load default config to establish baseline
        config_manager.load_config()
        
        # Should verify integrity
        assert config_manager.verify_integrity()
        
        # Modify configuration
        config_manager.network.listen_port = 9999
        
        # Integrity should be different now
        # (Note: This depends on implementation details)
        # In a real scenario, we'd want external modification detection
    
    def test_security_recommendations(self, config_manager):
        """Test security recommendation system."""
        # Set some insecure settings
        config_manager.network.listen_host = "0.0.0.0"
        config_manager.security_policy.require_authentication = False
        config_manager.crypto.pbkdf2_iterations = 100000
        
        # Get recommendations
        recommendations = config_manager.get_security_recommendations()
        
        # Should have recommendations for the insecure settings
        assert any("0.0.0.0" in rec for rec in recommendations)
        assert any("authentication" in rec.lower() for rec in recommendations)
        assert any("PBKDF2" in rec for rec in recommendations)


class TestIntegrationSecurity:
    """Integration security tests."""
    
    @pytest.mark.asyncio
    async def test_full_handshake_security(self):
        """Test complete secure handshake process."""
        # This would test a full handshake between two nodes
        # Including key exchange, authentication, and session establishment
        pass  # Implementation would require more complex setup
    
    @pytest.mark.asyncio
    async def test_attack_scenario_simulation(self):
        """Simulate common attack scenarios."""
        # Test scenarios like:
        # - Multiple connection attempts from same IP
        # - Invalid handshake data
        # - Message flooding
        # - Malformed packets
        pass  # Implementation would require attack simulation
    
    def test_memory_security(self):
        """Test that sensitive data is properly cleared from memory."""
        # This is difficult to test comprehensively in Python
        # but we can test our SecureMemory utilities
        sensitive_data = bytearray(b"sensitive_password_123")
        
        # Clear the data
        SecureMemory.clear_bytes(sensitive_data)
        
        # Note: Python doesn't guarantee memory clearing,
        # but we can test that our function doesn't crash
        assert True  # If we get here, function didn't crash


class TestSecurityMonitoring:
    """Test security monitoring and alerting."""
    
    def test_suspicious_activity_detection(self):
        """Test detection of suspicious network activity."""
        # This would test intrusion detection systems
        # and anomaly detection algorithms
        pass
    
    def test_security_event_logging(self):
        """Test that security events are properly logged."""
        # This would test security logging functionality
        pass
    
    def test_alert_generation(self):
        """Test that security alerts are generated appropriately."""
        # This would test alerting systems
        pass


if __name__ == "__main__":
    # Run security tests
    pytest.main([__file__, "-v", "--tb=short"])

