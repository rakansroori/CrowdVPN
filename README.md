main website:
http://crowdvpn.infy.uk/

# Crowd VPN

A decentralized peer-to-peer VPN system where every connected client also acts as a server node, creating a crowded network of interconnected IPs.

## Overview

Crowd VPN implements a novel approach to VPN technology where:
- Every client that connects becomes a potential exit node for other users
- Traffic is distributed across multiple peer nodes for enhanced privacy
- No single central server controls all traffic
- Network grows stronger as more users join

## Architecture

```
User A ←→ Node B ←→ Node C ←→ Internet
  ↑         ↑         ↑
  └─────────┼─────────┘
            ↓
          Node D
```

## Features

- **Decentralized Network**: No single point of failure
- **Dynamic Routing**: Automatic path selection through peer nodes
- **Load Balancing**: Traffic distributed across available nodes
- **Encryption**: End-to-end encrypted tunnels
- **NAT Traversal**: Automatic firewall and NAT bypass
- **Bandwidth Sharing**: Fair bandwidth allocation system

## Components

- `core/` - Core networking and routing logic
- `crypto/` - Encryption and security modules
- `p2p/` - Peer-to-peer discovery and management
- `client/` - Client application interface
- `server/` - Node server functionality
- `config/` - Configuration management
- `utils/` - Utility functions and helpers

## Installation

```bash
# Install dependencies
pip install -r requirements.txt

# Run as a node
python -m crowd_vpn.node

# Connect as client
python -m crowd_vpn.client
```

## Usage

### GUI Application

For the graphical user interface:

```bash
# Launch the GUI
python launch_gui.py

# Or directly run the main GUI
python crowd_vpn_gui.py
```

**GUI Features:**
- Native desktop interface using tkinter
- Country selection for exit location
- Real-time connection monitoring
- Built-in settings configuration
- Live activity logging
- One-click connection management
- Connection statistics and uptime tracking

### Command Line Interface

#### Running a Node
```bash
python -m crowd_vpn start --port 8080 --type hybrid
```

#### Connecting to Specific Countries
```bash
# Connect via US servers
python -m crowd_vpn connect --bootstrap us-east-1.crowdvpn.com:8080

# Connect via European servers  
python -m crowd_vpn connect --bootstrap de-frankfurt-1.crowdvpn.com:8080

# Connect via Asian servers
python -m crowd_vpn connect --bootstrap jp-tokyo-1.crowdvpn.com:8080
```

#### Geographic Routing
```bash
# Start node with geographic preferences
python -m crowd_vpn start --routing reputation_based --verbose
```

## Security Considerations

- All traffic is encrypted using modern cryptographic standards
- Node reputation system prevents malicious actors
- Optional exit node filtering for enhanced security
- Traffic analysis resistance through multi-hop routing
