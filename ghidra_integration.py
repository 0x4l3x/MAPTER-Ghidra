"""
Ghidra Integration Module for Dash Application
===============================================
Provides utilities and callbacks for bidirectional communication
between the Dash web app and Ghidra via HTTP.

This module handles:
- Sending navigation requests to Ghidra
- Click event callbacks for Plotly graphs
- Error handling and validation
- Connection health checks
"""

import requests
import json
from typing import Optional, Dict, Any, List, Tuple
import logging

import numpy as np

# Configure logging
logger = logging.getLogger(__name__)


class GhidraClient:
    """
    Client for communicating with Ghidra navigation server.
    """
    
    def __init__(self, host: str = "127.0.0.1", port: int = 9999, timeout: float = 5.0):
        """
        Initialize Ghidra client.
        
        Args:
            host: Ghidra server host address
            port: Ghidra server port
            timeout: Request timeout in seconds
        """
        self.host = host
        self.port = port
        self.timeout = timeout
        self.base_url = f"http://{host}:{port}"
        self._server_available = None  # Cache server status
    
    def check_server(self) -> bool:
        """
        Check if Ghidra server is running and accessible.
        
        Returns:
            True if server is accessible, False otherwise
        """
        try:
            response = requests.get(
                f"{self.base_url}/status",
                timeout=self.timeout
            )
            if response.status_code == 200:
                data = response.json()
                self._server_available = data.get('status') == 'running'
                return self._server_available
        except requests.exceptions.RequestException as e:
            logger.debug(f"Ghidra server not available: {e}")
            self._server_available = False
        
        return False
    
    def navigate_to_function(
        self,
        address: Optional[str] = None,
        name: Optional[str] = None,
        binary_name: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Send navigation request to Ghidra.
        
        Args:
            address: Function address (hex string, e.g., "0x401000")
            name: Function name
            binary_name: Binary name for validation
        
        Returns:
            Dictionary with response data:
            {
                'success': bool,
                'message': str,
                'error': str (if failed),
                ...
            }
        """
        if not address and not name:
            return {
                'success': False,
                'error': 'Either address or name must be provided'
            }
        
        # Build request payload
        payload = {}
        if address:
            payload['address'] = address
        if name:
            payload['name'] = name
        if binary_name:
            payload['binary_name'] = binary_name
        
        try:
            response = requests.post(
                f"{self.base_url}/navigate",
                json=payload,
                timeout=self.timeout,
                headers={'Content-Type': 'application/json'}
            )
            
            # Parse response
            result = response.json()
            
            # Log navigation result
            if result.get('success'):
                logger.info(
                    f"Successfully navigated to function: "
                    f"{result.get('function_name', name or address)} "
                    f"at {result.get('address', address)}"
                )
            else:
                logger.warning(
                    f"Navigation failed: {result.get('error', 'Unknown error')}"
                )
            
            return result
        
        except requests.exceptions.Timeout:
            error_msg = f"Request to Ghidra server timed out after {self.timeout}s"
            logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg
            }
        
        except requests.exceptions.ConnectionError:
            error_msg = (
                f"Could not connect to Ghidra server at {self.base_url}. "
                "Make sure the MapterBridge extension's navigation server is running."
            )
            logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg
            }
        
        except requests.exceptions.RequestException as e:
            error_msg = f"Request failed: {str(e)}"
            logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg
            }
        
        except json.JSONDecodeError:
            error_msg = "Invalid JSON response from Ghidra server"
            logger.error(error_msg)
            return {
                'success': False,
                'error': error_msg
            }
    
    def get_current(self, timeout: Optional[float] = None) -> Optional[Dict[str, Any]]:
        """
        Ask Ghidra which function is under the CodeBrowser cursor (GET /current).

        Args:
            timeout: Request timeout in seconds (defaults to the client timeout).
                Pollers should pass a short one.

        Returns:
            ``{'program', 'program_sha256', 'function_name', 'entry_address',
            'address'}`` (values may be None; program_sha256 is None when the
            MapterBridge version does not report it), or None if the server is unreachable or the reply is
            not usable.
        """
        try:
            response = requests.get(
                f"{self.base_url}/current",
                timeout=self.timeout if timeout is None else timeout
            )
            if response.status_code != 200:
                logger.debug(f"GET /current returned HTTP {response.status_code}")
                return None
            data = response.json()
        except (requests.exceptions.RequestException, ValueError) as e:
            logger.debug(f"Ghidra /current not available: {e}")
            return None
        if not isinstance(data, dict) or not data.get('success'):
            return None
        return {key: data.get(key)
                for key in ('program', 'program_sha256', 'function_name',
                            'entry_address', 'address')}

    def shutdown_server(self) -> Dict[str, Any]:
        """
        Send shutdown request to Ghidra server.
        
        Returns:
            Response dictionary
        """
        try:
            response = requests.post(
                f"{self.base_url}/shutdown",
                timeout=self.timeout
            )
            return response.json()
        except Exception as e:
            return {
                'success': False,
                'error': f'Shutdown request failed: {str(e)}'
            }


def parse_hex_offset(value) -> Optional[int]:
    """
    Parse a dataset ``offset`` / Ghidra address into an int.

    Accepts "0x401000", "401000", "0X00401000" and plain ints. Addresses are
    compared as integers because Ghidra and the datasets format hex
    differently (zero padding, prefix).

    Returns:
        The integer value, or None if it is missing or not hex.
    """
    if value is None:
        return None
    if isinstance(value, (int, np.integer)) and not isinstance(value, bool):
        return int(value)
    text = str(value).strip().lower()
    if text.startswith('0x'):
        text = text[2:]
    try:
        return int(text, 16)
    except ValueError:
        return None


def match_binary_name(program_name: str, binary_names,
                      program_sha256: Optional[str] = None) -> Tuple[Optional[str], List[str]]:
    """
    Find which dataset ``binary_name`` a Ghidra program name refers to.

    Mirror of MapterBridge's ProgramNameMatcher: the Ghidra program name is the
    full (possibly suffixed) hash and dataset names may be truncated, so the
    tiers are, case-insensitive: binary_name is a prefix of the program's
    SHA-256 (only when ``program_sha256`` is given; the most reliable, as it
    does not depend on the program name), exact, program name starts with
    binary_name, program name contains binary_name. The first tier with a
    single hit wins; ties are ambiguous and never guessed.

    Returns:
        (binary_name or None, candidates) — candidates lists the tied names
        when the match is ambiguous, else it is empty or the single match.
    """
    sha = str(program_sha256).strip().lower() if program_sha256 else ''
    if not program_name and not sha:
        return None, []
    target = str(program_name or '').strip().lower()
    names = [str(b) for b in dict.fromkeys(binary_names) if b is not None and str(b)]
    tiers = (
        lambda n: bool(sha) and sha.startswith(n),
        lambda n: bool(target) and n == target,
        lambda n: bool(target) and target.startswith(n),
        lambda n: bool(target) and n in target,
    )
    hits: List[str] = []
    for tier in tiers:
        hits = [b for b in names if tier(b.lower())]
        if len(hits) == 1:
            return hits[0], hits
    return None, hits


