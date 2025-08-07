# Contributing to Crowd VPN

We welcome contributions to Crowd VPN! This document provides guidelines for contributing to the project.

## Getting Started

1. Fork the repository
2. Clone your fork:
   ```bash
   git clone https://github.com/yourusername/crowd-vpn.git
   cd crowd-vpn
   ```
3. Install development dependencies:
   ```bash
   pip install -r dev-requirements.txt
   ```

## Development Setup

1. Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install the package in development mode:
   ```bash
   pip install -e .
   ```

## Code Style

- Follow PEP 8 guidelines
- Use type hints where appropriate
- Run code formatting before committing:
  ```bash
  black .
  isort .
  ```

- Run linting:
  ```bash
  flake8 .
  mypy .
  ```

## Testing

- Write tests for new features
- Run the test suite:
  ```bash
  pytest
  ```

- Run tests with coverage:
  ```bash
  pytest --cov=crowd_vpn
  ```

## Submitting Changes

1. Create a new branch for your feature/fix:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Make your changes and commit them:
   ```bash
   git add .
   git commit -m "Add your descriptive commit message"
   ```

3. Push to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

4. Create a Pull Request on GitHub

## Pull Request Guidelines

- Provide a clear description of the changes
- Include any relevant issue numbers
- Ensure all tests pass
- Update documentation if needed
- Add tests for new functionality

## Security

If you discover a security vulnerability, please send an email to security@crowdvpn.example.com instead of opening a public issue.

## Code of Conduct

This project adheres to a Code of Conduct. By participating, you are expected to uphold this code.

