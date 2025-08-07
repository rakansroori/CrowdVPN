"""Command-line interface for Crowd VPN."""

import asyncio
import click
import json
import sys
from typing import Optional

from .node import CrowdVPNNode
from .core.network import NodeType
from .core.router import RoutingAlgorithm


@click.group()
@click.version_option(version='0.1.0')
def cli():
    """Crowd VPN - Decentralized peer-to-peer VPN system."""
    pass


@cli.command()
@click.option('--port', '-p', default=8080, help='Port to listen on')
@click.option('--type', 'node_type', type=click.Choice(['client', 'relay', 'exit', 'hybrid']), 
              default='hybrid', help='Node type')
@click.option('--bootstrap', '-b', multiple=True, help='Bootstrap node (host:port)')
@click.option('--routing', type=click.Choice(['random', 'shortest_path', 'load_balanced', 'reputation_based']),
              default='reputation_based', help='Routing algorithm')
@click.option('--config', '-c', help='Configuration file path')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--daemon', '-d', is_flag=True, help='Run as daemon')
def start(port: int, node_type: str, bootstrap: tuple, routing: str, 
          config: Optional[str], verbose: bool, daemon: bool):
    """Start a Crowd VPN node."""
    
    if verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Convert string types to enums
    node_type_enum = NodeType(node_type)
    routing_enum = RoutingAlgorithm(routing)
    
    # Create node
    node = CrowdVPNNode(
        port=port,
        node_type=node_type_enum,
        bootstrap_nodes=list(bootstrap),
        routing_algorithm=routing_enum
    )
    
    click.echo(f"Starting Crowd VPN node on port {port}...")
    click.echo(f"Node type: {node_type}")
    click.echo(f"Bootstrap nodes: {list(bootstrap)}")
    
    try:
        if daemon:
            # TODO: Implement proper daemon mode
            click.echo("Daemon mode not yet implemented")
            sys.exit(1)
        else:
            asyncio.run(node.start())
    except KeyboardInterrupt:
        click.echo("\nShutting down...")
        asyncio.run(node.stop())
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--host', '-h', default='localhost', help='Node host')
@click.option('--port', '-p', default=8080, help='Node port')
@click.option('--format', 'output_format', type=click.Choice(['json', 'table']), 
              default='table', help='Output format')
def status(host: str, port: int, output_format: str):
    """Get status of a running Crowd VPN node."""
    
    async def get_status():
        try:
            import aiohttp
            
            # This would connect to a status endpoint on the node
            # For now, just show placeholder data
            status_data = {
                'node_id': 'placeholder_id',
                'node_type': 'hybrid',
                'port': port,
                'running': True,
                'connected_peers': 0,
                'known_peers': 0,
                'active_routes': 0
            }
            
            if output_format == 'json':
                click.echo(json.dumps(status_data, indent=2))
            else:
                click.echo("Crowd VPN Node Status:")
                click.echo(f"  Node ID: {status_data['node_id']}")
                click.echo(f"  Type: {status_data['node_type']}")
                click.echo(f"  Port: {status_data['port']}")
                click.echo(f"  Status: {'Running' if status_data['running'] else 'Stopped'}")
                click.echo(f"  Connected Peers: {status_data['connected_peers']}")
                click.echo(f"  Known Peers: {status_data['known_peers']}")
                click.echo(f"  Active Routes: {status_data['active_routes']}")
                
        except Exception as e:
            click.echo(f"Error getting status: {e}", err=True)
            sys.exit(1)
    
    asyncio.run(get_status())


@cli.command()
@click.option('--bootstrap', '-b', required=True, help='Bootstrap node (host:port)')
@click.option('--routing', type=click.Choice(['random', 'shortest_path', 'load_balanced', 'reputation_based']),
              default='reputation_based', help='Routing algorithm')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def connect(bootstrap: str, routing: str, verbose: bool):
    """Connect to the Crowd VPN network as a client."""
    
    if verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Create client node
    node = CrowdVPNNode(
        port=0,  # Client doesn't need to listen
        node_type=NodeType.CLIENT,
        bootstrap_nodes=[bootstrap],
        routing_algorithm=RoutingAlgorithm(routing)
    )
    
    click.echo(f"Connecting to Crowd VPN via {bootstrap}...")
    
    async def connect_client():
        try:
            await node.start()
            success = await node.connect_to_network(bootstrap)
            if success:
                click.echo("Successfully connected to Crowd VPN network")
                click.echo("VPN tunnel is now active")
                # Keep the connection alive
                while node.running:
                    await asyncio.sleep(1)
            else:
                click.echo("Failed to connect to Crowd VPN network", err=True)
                sys.exit(1)
        except KeyboardInterrupt:
            click.echo("\nDisconnecting...")
        finally:
            await node.stop()
    
    try:
        asyncio.run(connect_client())
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


@cli.command()
@click.option('--output', '-o', type=click.File('w'), default='-', 
              help='Output file (default: stdout)')
def generate_config(output):
    """Generate a default configuration file."""
    
    config_template = """
# Crowd VPN Node Configuration

# Network settings
network:
  listen_port: 8080
  node_type: "hybrid"  # client, relay, exit, hybrid
  max_connections: 50

# Bootstrap nodes
bootstrap:
  nodes:
    - "bootstrap1.example.com:8080"
    - "bootstrap2.example.com:8080"

# Routing configuration
routing:
  algorithm: "reputation_based"
  max_hops: 5

# Security settings
security:
  key_size: 2048
  enable_signature_verification: true

# Logging
logging:
  level: "INFO"
  file: "crowd_vpn.log"
""".strip()
    
    output.write(config_template)
    if output != sys.stdout:
        click.echo(f"Configuration written to {output.name}")


@cli.command()
def peers():
    """List connected peers."""
    # This would connect to a running node and get peer information
    click.echo("Peer listing not yet implemented")
    click.echo("This feature will show connected peers and their status")


@cli.command()
def routes():
    """Show active routes."""
    # This would show current routing table
    click.echo("Route listing not yet implemented")
    click.echo("This feature will show active routes through the network")


@cli.command()
def gui():
    """Launch the modern Python GUI interface."""
    import subprocess
    import os
    
    try:
        click.echo("Starting Crowd VPN GUI Application...")
        click.echo("")
        click.echo("🖥️ Desktop Application")
        click.echo("")
        click.echo("Features:")
        click.echo("  • Native desktop interface")
        click.echo("  • Real-time connection monitoring")
        click.echo("  • Easy VPN control and settings")
        click.echo("  • Live activity logs")
        click.echo("  • Cross-platform compatibility")
        
        click.echo("\nStarting GUI application...")
        
        # Try to run the GUI application directly
        gui_launcher = os.path.join(os.getcwd(), 'launch_gui.py')
        gui_main = os.path.join(os.getcwd(), 'crowd_vpn_gui.py')
        
        if os.path.exists(gui_launcher):
            click.echo("Launching GUI application...")
            subprocess.run([sys.executable, gui_launcher])
        elif os.path.exists(gui_main):
            click.echo("Launching GUI application...")
            subprocess.run([sys.executable, gui_main])
        else:
            click.echo("GUI files not found. Please ensure crowd_vpn_gui.py exists.")
        
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        click.echo("Please run 'python crowd_vpn_gui.py' manually to launch the GUI.")
        sys.exit(1)


if __name__ == '__main__':
    cli()

