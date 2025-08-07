#!/usr/bin/env python3
"""Setup script for Crowd VPN."""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh.readlines() if line.strip() and not line.startswith("#")]

setup(
    name="crowd-vpn",
    version="1.0.0",
    author="Crowd VPN Team",
    author_email="dev@crowdvpn.example.com",
    description="A decentralized peer-to-peer VPN system",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/crowdvpn/crowd-vpn",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: System :: Networking",
        "Topic :: Internet :: Proxy Servers",
        "Topic :: Security :: Cryptography",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-asyncio>=0.21.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
        "analytics": [
            "numpy>=1.24.0",
            "networkx>=3.1",
        ]
    },
    entry_points={
        "console_scripts": [
            "crowd-vpn-node=crowd_vpn.node:main",
            "crowd-vpn-gui=crowd_vpn_gui:main",
            "crowd-vpn=launch_gui:main",
        ],
        "gui_scripts": [
            "crowd-vpn-gui=crowd_vpn_gui:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)

