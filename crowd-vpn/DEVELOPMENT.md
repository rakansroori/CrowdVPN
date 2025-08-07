# Crowd VPN Development Guide

## Project Structure

```
crowd-vpn/
├── crowd_vpn/                 # Main package
│   ├── __init__.py           # Package initialization
│   ├── __main__.py           # Module entry point
│   ├── cli.py                # Command-line interface
│   ├── node.py               # Main node application
│   ├── core/                 # Core networking components
│   │   ├── network.py        # Network management
│   │   └── router.py         # Traffic routing
│   ├── crypto/               # Cryptographic components
│   │   └── encryption.py     # Encryption utilities
│   └── p2p/                  # Peer-to-peer components
│       └── discovery.py      # Peer discovery
├── config/                   # Configuration files
├── tests/                    # Test suite
├── requirements.txt          # Python dependencies
├── setup.py                  # Package setup
└── README.md                # Project documentation
```

## Key Components

### 1. NetworkManager (`core/network.py`)
- Manages peer connections and network communication
- Handles incoming/outgoing connections
- Maintains peer registry
- Supports different node types (client, relay, exit, hybrid)

### 2. TrafficRouter (`core/router.py`)
- Routes traffic through the peer network
- Implements multiple routing algorithms
- Manages active routes and load balancing
- Handles packet forwarding

### 3. PeerDiscovery (`p2p/discovery.py`)
- Discovers and maintains peer connections
- Implements DHT-like peer storage
- Supports bootstrap nodes and local discovery
- Manages peer announcements

### 4. CryptoManager (`crypto/encryption.py`)
- Handles all cryptographic operations
- Key generation and management
- End-to-end encryption using AES-GCM
- Digital signatures for authentication

### 5. CrowdVPNNode (`node.py`)
- Main application class that coordinates all components
- Handles startup, shutdown, and maintenance tasks
- Provides status monitoring and control

## Development Setup

### Prerequisites
- Python 3.8 or higher
- pip package manager

### Installation

1. Clone the repository:
   ```bash
   git clone https://github.com/crowdvpn/crowd-vpn.git
   cd crowd-vpn
   ```

2. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Linux/Mac
   # or
   venv\Scripts\activate.bat  # Windows
   ```

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   pip install -e .  # Install in development mode
   ```

### Running Tests

```bash
pytest tests/
```

### Code Formatting

```bash
black crowd_vpn/
flake8 crowd_vpn/
mypy crowd_vpn/
```

## Usage Examples

### Starting a Node

```bash
# Start a hybrid node (acts as both relay and exit)
python -m crowd_vpn start --port 8080 --type hybrid

# Start with bootstrap nodes
python -m crowd_vpn start --bootstrap node1.example.com:8080 --bootstrap node2.example.com:8080

# Start with specific routing algorithm
python -m crowd_vpn start --routing reputation_based --verbose
```

### Connecting as a Client

```bash
# Connect to the network via a bootstrap node
python -m crowd_vpn connect --bootstrap node1.example.com:8080
```

### Checking Status

```bash
# Get node status
python -m crowd_vpn status --host localhost --port 8080

# JSON output
python -m crowd_vpn status --format json
```

### Generating Configuration

```bash
# Generate default configuration
python -m crowd_vpn generate-config > config.yaml
```

## Architecture Details

### Node Types

1. **Client**: Only consumes VPN services, doesn't relay traffic
2. **Relay**: Forwards traffic for other nodes but doesn't act as exit
3. **Exit**: Acts as final hop to internet destinations
4. **Hybrid**: Combines relay and exit functionality (recommended)

### Routing Algorithms

1. **Random**: Randomly selects peers for routing
2. **Shortest Path**: Uses latency-based path selection
3. **Load Balanced**: Distributes traffic based on peer capacity
4. **Reputation Based**: Prioritizes high-reputation peers (default)

### Security Features

- RSA-2048 key pairs for node identity
- AES-GCM encryption for session data
- HKDF for session key derivation
- Digital signatures for message authentication
- Reputation system to prevent malicious nodes

### Network Protocol

The protocol uses JSON messages over TCP with the following message types:
- `peer_announcement`: Node presence announcement
- `peer_list_request`: Request for known peers
- `forward_packet`: Traffic forwarding request
- `handshake`: Initial connection negotiation

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with tests
4. Ensure code passes linting and tests
5. Submit a pull request

## Security Considerations

⚠️ **Important**: This is a prototype implementation for educational purposes. Before using in production:

1. Implement proper cryptographic key exchange (ECDH)
2. Add comprehensive input validation
3. Implement DOS protection mechanisms
4. Add traffic analysis resistance features
5. Conduct security audits
6. Implement proper logging and monitoring

## Performance Considerations

- Uses asyncio for high-performance networking
- Connection pooling for efficient peer management
- Configurable buffer sizes and timeouts
- Route caching to reduce lookup overhead
- Bandwidth monitoring and throttling

## Future Enhancements

1. **GUI Client**: Desktop application for easy use
2. **Mobile Apps**: iOS and Android clients
3. **Advanced Routing**: Implement Tor-like onion routing
4. **Incentive System**: Token-based reward system for relay nodes
5. **Traffic Obfuscation**: Advanced techniques to bypass censorship
6. **Network Visualization**: Real-time network topology display
7. **Load Balancing**: Intelligent traffic distribution
8. **Exit Node Policies**: Configurable content filtering
9. **Statistics Dashboard**: Web-based monitoring interface
10. **Docker Support**: Containerized deployment

