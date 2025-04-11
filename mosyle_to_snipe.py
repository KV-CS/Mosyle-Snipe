#!/usr/bin/env python3
"""
Mosyle to Snipe-IT Sync Script

This script synchronizes device information between Mosyle MDM and Snipe-IT asset management system.
It pulls device data from Mosyle and either updates existing assets or creates new ones in Snipe-IT.
It also provides functionality to generate a JWT token for Mosyle API authentication.

Usage:
    # Run the sync process
    python mosyle_to_snipe.py [--config CONFIG] [--device-type TYPE] [--dry-run] [--batch-size SIZE] [--batch-delay DELAY]
    
    # Generate a JWT token
    python mosyle_to_snipe.py token [--email EMAIL] [--password PASSWORD] [--access-token TOKEN] [--config CONFIG]

Features:
- JWT token generation for Mosyle API authentication (required as of February 2024)
- Retrieves device information from Mosyle MDM with pagination support
- Creates or updates assets in Snipe-IT
- Creates models in Snipe-IT if they don't exist
- Maps Mosyle device attributes to Snipe-IT custom fields
- Handles device-to-user assignments
- Sets purchase dates based on Mosyle first enrollment dates
- Advanced rate limiting with exponential backoff
- Batch processing to reduce API load
- Retry logic for failed requests
- Dry run mode for testing

Requirements:
- Python 3.6+
- requests module
- json module
"""

import json
import datetime
import time
import logging
import sys
import os
import re
import requests
import argparse
from typing import Dict, List, Union, Optional, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("mosyle_snipeit_sync.log"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

def get_jwt_token(email: str, password: str, access_token: str, api_url: str = "https://managerapi.mosyle.com/v2") -> Optional[str]:
    """
    Get JWT token from Mosyle API
    
    Args:
        email: Mosyle administrator email
        password: Mosyle administrator password
        access_token: Mosyle access token
        api_url: Mosyle API URL
        
    Returns:
        JWT token string if successful, None otherwise
    """
    endpoint = f"{api_url}/login"
    
    headers = {
        'Content-Type': 'application/json'
    }
    
    # Create payload
    payload = {
        "email": email,
        "password": password,
        "accessToken": access_token
    }
    
    try:
        logger.info(f"Sending token request to: {endpoint}")
        logger.info(f"Using email: {email}")
        
        response = requests.post(endpoint, headers=headers, json=payload)
        
        logger.info(f"Response status code: {response.status_code}")
        
        if response.status_code != 200:
            logger.error(f"Error response: {response.text[:200]}...")
        
        response.raise_for_status()
        
        # Get token from Authorization header
        if 'Authorization' in response.headers:
            logger.info("Successfully received Authorization header")
            return response.headers['Authorization']
        else:
            logger.error("No Authorization header found in response")
            logger.debug(f"Available headers: {list(response.headers.keys())}")
            if len(response.text) < 1000:
                logger.debug(f"Response body: {response.text}")
            return None
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Error getting JWT token: {str(e)}")
        return None

def token_command(args: argparse.Namespace) -> None:
    """
    Handle the JWT token generation command
    
    Args:
        args: Command line arguments
    """
    # Load configuration file
    try:
        with open(args.config, 'r') as f:
            config = json.load(f)
    except Exception as e:
        logger.error(f"Error reading configuration file: {str(e)}")
        sys.exit(1)
    
    # Get credentials from config file
    email = config.get('mosyle', {}).get('email')
    password = config.get('mosyle', {}).get('password')
    access_token = config.get('mosyle', {}).get('access_token')
    api_url = args.api_url or config.get('mosyle', {}).get('api_url', 'https://managerapi.mosyle.com/v2')
    
    if not email or not password or not access_token:
        logger.error("Error: Mosyle email, password, and access token are required in the config file.")
        sys.exit(1)
    
    logger.info("Requesting JWT token from Mosyle...")
    logger.info(f"Using email: {email} and API URL: {api_url}")
    
    token = get_jwt_token(email, password, access_token, api_url)
    
    if token:
        logger.info("\nSuccess! JWT token received:")
        print("=" * 80)
        print(token)
        print("=" * 80)
        
        # Update config file
        try:
            if 'mosyle' not in config:
                config['mosyle'] = {}
            
            config['mosyle']['jwt_token'] = token
            
            with open(args.config, 'w') as f:
                json.dump(config, f, indent=2)
            
            logger.info(f"\nUpdated JWT token in {args.config}")
        except Exception as e:
            logger.error(f"\nFailed to update config file: {str(e)}")
            logger.info("\nAdd this token to your settings.json file under the mosyle section:")
            logger.info('  "jwt_token": "' + token + '"')
        
        logger.info("\nNote: JWT tokens have an expiration time. You may need to regenerate this token periodically.")
    else:
        logger.error("Failed to get JWT token")
        sys.exit(1)

class MosyleAPI:
    """Interface for Mosyle API operations"""
    
    def __init__(self, config: Dict, config_file: str = 'settings.json'):
        """Initialize Mosyle API with configuration"""
        self.base_url = config['mosyle']['api_url']
        self.email = config['mosyle'].get('email', '')
        self.password = config['mosyle'].get('password', '')
        self.access_token = config['mosyle']['access_token']
        self.jwt_token = config['mosyle'].get('jwt_token', '')
        self.config_file = config_file
        self.config = config
        
        self.headers = {
            'Content-Type': 'application/json'
        }
        
        # Add JWT token as Authorization header if available
        if self.jwt_token:
            self.headers['Authorization'] = self.jwt_token
            logger.info("Using JWT token for Mosyle authentication")
        else:
            logger.warning("No JWT token found. Authentication will likely fail.")
            # Modern Mosyle API requires JWT token
    
    def refresh_token(self) -> bool:
        """
        Attempt to refresh the JWT token
        
        Returns:
            True if successful, False otherwise
        """
        if not self.email or not self.password or not self.access_token:
            logger.error("Cannot refresh JWT token: missing email, password, or access token in config")
            return False
            
        logger.info("Attempting to refresh JWT token...")
        
        token = get_jwt_token(self.email, self.password, self.access_token, self.base_url)
        
        if token:
            logger.info("Successfully obtained new JWT token")
            
            # Update token in memory
            self.jwt_token = token
            self.headers['Authorization'] = token
            
            # Update config in memory
            self.config['mosyle']['jwt_token'] = token
            
            # Update config file
            try:
                with open(self.config_file, 'w') as f:
                    json.dump(self.config, f, indent=2)
                logger.info(f"Updated JWT token in {self.config_file}")
                return True
            except Exception as e:
                logger.error(f"Failed to update config file with new JWT token: {str(e)}")
                return False
        else:
            logger.error("Failed to refresh JWT token")
            return False
    
    def _make_request(self, endpoint: str, method: str = 'POST', payload: Dict = None, retry_token: bool = True) -> Optional[Dict]:
        """
        Make a request to the Mosyle API with automatic token refresh
        
        Args:
            endpoint: API endpoint
            method: HTTP method (POST, GET)
            payload: Request payload
            retry_token: Whether to retry with token refresh if authentication fails
            
        Returns:
            Response data or None on failure
        """
        url = f"{self.base_url}/{endpoint}"
        
        try:
            logger.debug(f"Making {method} request to {url}")
            
            if method.upper() == 'POST':
                response = requests.post(url, headers=self.headers, json=payload)
            elif method.upper() == 'GET':
                response = requests.get(url, headers=self.headers)
            else:
                logger.error(f"Unsupported HTTP method: {method}")
                return None
                
            # Check for authentication errors
            if response.status_code == 401 or response.status_code == 403:
                logger.warning(f"Authentication failed (status code: {response.status_code})")
                
                if retry_token:
                    # Try to refresh token and retry
                    if self.refresh_token():
                        logger.info("Token refreshed, retrying request")
                        return self._make_request(endpoint, method, payload, retry_token=False)
                    else:
                        logger.error("Failed to refresh token")
                        return None
                else:
                    logger.error("Authentication failed and token refresh already attempted")
                    return None
            
            # Check for other HTTP errors
            response.raise_for_status()
            
            # Parse JSON response
            data = response.json()
            
            # Check for API errors
            if data.get('status') == 'error':
                error_msg = data.get('message', 'Unknown error')
                
                # Check if error is related to authentication
                if 'auth' in str(error_msg).lower() or 'token' in str(error_msg).lower() or 'login' in str(error_msg).lower():
                    logger.warning(f"API error suggests authentication issue: {error_msg}")
                    
                    if retry_token:
                        # Try to refresh token and retry
                        if self.refresh_token():
                            logger.info("Token refreshed, retrying request")
                            return self._make_request(endpoint, method, payload, retry_token=False)
                        else:
                            logger.error("Failed to refresh token")
                            return None
                    else:
                        logger.error("Authentication failed and token refresh already attempted")
                        return None
                else:
                    logger.error(f"API error: {error_msg}")
                    return None
            
            return data
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error: {str(e)}")
            return None
    
    def get_devices(self, device_type: str = 'all') -> List[Dict[str, Any]]:
        """
        Retrieve devices from Mosyle with pagination support
        
        Args:
            device_type: Type of devices to retrieve (ios, mac, tvos, or all)
                         If 'all', will query each device type separately and combine results
            
        Returns:
            List of device dictionaries
        """
        all_devices = []
        
        # Define valid device types
        valid_device_types = ['ios', 'mac', 'tvos']
        
        # If 'all' is specified, iterate through each valid device type
        types_to_query = valid_device_types if device_type == 'all' else [device_type]
        
        for current_type in types_to_query:
            # Track pagination
            page = 1
            has_more_pages = True
            type_devices = []
            
            # Set page size to 100 (higher than default 50)
            page_size = 100
            
            while has_more_pages:
                # Create proper payload for Mosyle API with pagination parameters
                payload = {
                    "accessToken": self.access_token,
                    "options": {
                        "os": current_type,
                        "page": page,
                        "page_size": page_size
                    }
                }
                
                logger.info(f"Requesting {current_type} devices (page {page})")
                
                # Use the new _make_request method for automatic token refresh
                data = self._make_request("listdevices", "POST", payload)
                
                if not data:
                    logger.error(f"Failed to get {current_type} devices (page {page})")
                    break
                
                # Extract devices from the response
                devices = []
                
                # The exact structure might vary based on Mosyle's API
                # Try different possible structures
                if 'devices' in data:
                    logger.debug(f"Found 'devices' in the response for {current_type}")
                    if isinstance(data['devices'], list):
                        devices = data['devices']
                    elif isinstance(data['devices'], dict):
                        # If it's a dict with device types as keys
                        for device_list in data['devices'].values():
                            if isinstance(device_list, list):
                                devices.extend(device_list)
                
                # Try alternative response formats
                elif 'response' in data:
                    logger.debug(f"Found 'response' in the data for {current_type}")
                    if isinstance(data['response'], dict) and 'devices' in data['response']:
                        # Direct access to devices in response
                        devices = data['response']['devices']
                    elif isinstance(data['response'], list) and data['response']:
                        if 'devices' in data['response'][0]:
                            devices_data = data['response'][0]['devices']
                            if isinstance(devices_data, list):
                                devices = devices_data
                            elif isinstance(devices_data, dict):
                                for device_list in devices_data.values():
                                    if isinstance(device_list, list):
                                        devices.extend(device_list)
                
                # Add devices from this page
                type_devices.extend(devices)
                logger.info(f"Retrieved {len(devices)} {current_type} devices from Mosyle (page {page})")
                
                # Check if we need to fetch more pages
                # If we received fewer devices than the page size, we're likely on the last page
                if len(devices) < page_size:
                    has_more_pages = False
                else:
                    page += 1
            
            # Add all devices for this type to the combined list
            logger.info(f"Total {current_type} devices retrieved: {len(type_devices)}")
            all_devices.extend(type_devices)
        
        logger.info(f"Grand total devices retrieved from Mosyle: {len(all_devices)}")
        return all_devices


class SnipeITAPI:
    """Interface for Snipe-IT API operations"""
    
    def __init__(self, config: Dict):
        """Initialize Snipe-IT API with configuration"""
        self.base_url = config['snipeit']['api_url'].rstrip('/')
        self.api_key = config['snipeit']['api_key']
        self.default_status = config['snipeit']['default_status']
        self.manufacturer_id = config['snipeit']['manufacturer_id']
        self.macos_category_id = config['snipeit']['macos_category_id']
        self.ios_category_id = config['snipeit']['ios_category_id']
        self.tvos_category_id = config['snipeit']['tvos_category_id']
        self.macos_fieldset_id = config['snipeit'].get('macos_fieldset_id', '')
        self.ios_fieldset_id = config['snipeit'].get('ios_fieldset_id', '')
        self.tvos_fieldset_id = config['snipeit'].get('tvos_fieldset_id', '')
        
        # Rate limiting settings
        self.rate_limit = int(config['snipeit'].get('rate_limit', 60))  # Default to 60 requests per minute
        self.rate_window = float(config['snipeit'].get('rate_window', 60.0))  # Default to 60 seconds
        
        # Rate limiting state
        self.request_timestamps = []
        self.last_429_time = 0
        self.backoff_multiplier = 1
        self.max_backoff = 60  # Maximum backoff in seconds
        
        self.headers = {
            'Accept': 'application/json',
            'Content-Type': 'application/json',
            'Authorization': f'Bearer {self.api_key}'
        }
    
    def _handle_rate_limiting(self):
        """
        Handle API rate limiting with improved algorithm including exponential backoff
        """
        current_time = time.time()
        
        # Clean up old timestamps
        self.request_timestamps = [ts for ts in self.request_timestamps if current_time - ts < self.rate_window]
        
        # Check if we're still in backoff period after a 429 error
        if self.last_429_time > 0:
            time_since_429 = current_time - self.last_429_time
            backoff_time = min(self.backoff_multiplier * 5, self.max_backoff)
            
            if time_since_429 < backoff_time:
                # Still in backoff period, sleep for remaining time
                sleep_time = backoff_time - time_since_429
                logger.info(f"In backoff period after 429 error. Sleeping for {sleep_time:.2f} seconds")
                time.sleep(sleep_time)
                # Reset backoff if we've completed a full backoff period
                self.last_429_time = 0
                self.backoff_multiplier = 1
                # Clean timestamps again after sleep
                current_time = time.time()
                self.request_timestamps = [ts for ts in self.request_timestamps if current_time - ts < self.rate_window]
        
        # Check if we're approaching rate limit
        if len(self.request_timestamps) >= self.rate_limit:
            # Calculate when the oldest request will expire from the window
            oldest_timestamp = min(self.request_timestamps)
            time_until_slot_available = (oldest_timestamp + self.rate_window) - current_time
            
            # Add a small buffer to be safe
            buffer_time = 0.5
            sleep_time = time_until_slot_available + buffer_time
            
            logger.info(f"Rate limit approaching ({len(self.request_timestamps)}/{self.rate_limit} requests). "
                       f"Sleeping for {sleep_time:.2f} seconds")
            
            time.sleep(sleep_time)
            current_time = time.time()
            
            # Clean up timestamps again after sleeping
            self.request_timestamps = [ts for ts in self.request_timestamps if current_time - ts < self.rate_window]
        
        # Add current request to timestamps
        self.request_timestamps.append(current_time)
    
    def _make_request(self, method: str, endpoint: str, json_data: Optional[Dict] = None) -> requests.Response:
        """
        Make a request to the Snipe-IT API with rate limiting and retry logic
        
        Args:
            method: HTTP method (GET, POST, PUT, etc.)
            endpoint: API endpoint
            json_data: JSON data for POST/PUT requests
            
        Returns:
            Response object
        """
        max_retries = 3
        retry_count = 0
        
        while retry_count < max_retries:
            try:
                # Apply rate limiting before making request
                self._handle_rate_limiting()
                
                url = f"{self.base_url}/{endpoint}"
                
                if method.upper() == 'GET':
                    response = requests.get(url, headers=self.headers)
                elif method.upper() == 'POST':
                    response = requests.post(url, headers=self.headers, json=json_data)
                elif method.upper() == 'PUT':
                    response = requests.put(url, headers=self.headers, json=json_data)
                else:
                    raise ValueError(f"Unsupported HTTP method: {method}")
                
                # Handle rate limiting response
                if response.status_code == 429:
                    self.last_429_time = time.time()
                    self.backoff_multiplier *= 2  # Exponential backoff
                    
                    # Get retry-after header if available, otherwise use exponential backoff
                    retry_after = response.headers.get('Retry-After')
                    if retry_after:
                        try:
                            sleep_time = float(retry_after)
                        except (ValueError, TypeError):
                            sleep_time = min(self.backoff_multiplier * 5, self.max_backoff)
                    else:
                        sleep_time = min(self.backoff_multiplier * 5, self.max_backoff)
                    
                    logger.warning(f"Rate limit hit (429 response). Retry {retry_count+1}/{max_retries}. "
                                  f"Backing off for {sleep_time:.2f} seconds.")
                    
                    time.sleep(sleep_time)
                    retry_count += 1
                    continue
                
                # Check for HTTP errors
                response.raise_for_status()
                
                # Extract context info for better error messages
                asset_info = ""
                if endpoint.startswith('api/v1/hardware/'):
                    # Extract asset ID from endpoint for better error context
                    asset_parts = endpoint.split('/')
                    if len(asset_parts) > 3:
                        asset_info = f" (Asset ID/Serial: {asset_parts[-1]})"
                
                # Include asset information in payload if available
                if not asset_info and json_data and ('serial' in json_data or 'asset_tag' in json_data):
                    serial = json_data.get('serial', 'Unknown')
                    asset_tag = json_data.get('asset_tag', 'Unknown')
                    asset_info = f" (Serial: {serial}, Asset Tag: {asset_tag})"
                
                # Check for API errors (Snipe-IT still returns 200 OK even for errors)
                data = response.json()
                if data.get('status') == 'error':
                    error_msg = data.get('messages', 'Unknown error')
                    logger.error(f"Snipe-IT API error{asset_info}: {error_msg}")
                
                # Success, return response
                return response
                
            except requests.exceptions.RequestException as e:
                # Only retry certain types of exceptions
                if isinstance(e, (requests.exceptions.ConnectionError, requests.exceptions.Timeout)) or (
                        hasattr(e, 'response') and e.response is not None and e.response.status_code == 429):
                    
                    retry_count += 1
                    if retry_count < max_retries:
                        # Use exponential backoff
                        sleep_time = 2 ** retry_count
                        logger.warning(f"Request error: {str(e)}. Retry {retry_count}/{max_retries}. "
                                      f"Backing off for {sleep_time} seconds.")
                        time.sleep(sleep_time)
                        continue
                
                # Try to extract context for better error messages
                context_info = ""
                if endpoint.startswith('api/v1/hardware/'):
                    # Extract asset ID from endpoint
                    asset_parts = endpoint.split('/')
                    if len(asset_parts) > 3:
                        context_info = f" for asset {asset_parts[-1]}"
                
                logger.error(f"Error making request to Snipe-IT{context_info}: {str(e)}")
                raise
    
    def find_asset_by_serial(self, serial_number: str) -> Optional[Dict]:
        """
        Find an asset in Snipe-IT by serial number
        
        Args:
            serial_number: Device serial number
            
        Returns:
            Asset dictionary or None if not found
        """
        try:
            response = self._make_request('GET', f"api/v1/hardware/byserial/{serial_number}")
            data = response.json()
            
            if data.get('status') == 'error':
                if 'Asset does not exist' in str(data.get('messages', '')):
                    logger.info(f"Asset with serial number {serial_number} not found in Snipe-IT")
                else:
                    logger.error(f"Snipe-IT API error for device {serial_number}: {data.get('messages', 'Unknown error')}")
                return None
                
            if data.get('total', 0) == 0:
                logger.info(f"Asset with serial number {serial_number} not found in Snipe-IT")
                return None
                
            return data.get('rows', [])[0] if data.get('rows') else None
            
        except Exception as e:
            logger.error(f"Error finding asset by serial {serial_number}: {str(e)}")
            return None
    
    def check_serial_exists(self, serial_number: str) -> Optional[Dict]:
        """
        Check if a serial number exists in Snipe-IT (case-insensitive)
        
        Args:
            serial_number: Device serial number
            
        Returns:
            Asset dictionary or None if not found
        """
        try:
            # Use the search endpoint instead of direct lookup
            response = self._make_request('GET', f"api/v1/hardware?search={serial_number}")
            data = response.json()
            
            if data.get('status') == 'error' or data.get('total', 0) == 0:
                return None
                
            # Look through results for matching serial (case-insensitive)
            for asset in data.get('rows', []):
                asset_serial = asset.get('serial', '')
                if asset_serial.lower() == serial_number.lower():
                    logger.info(f"Found asset with serial {asset_serial} (ID: {asset.get('id')}) using case-insensitive search")
                    return asset
            
            return None
            
        except Exception as e:
            logger.error(f"Error checking if serial exists: {str(e)}")
            return None
    
    def search_asset_by_serial(self, serial_number: str) -> Optional[Dict]:
        """
        Search for an asset in Snipe-IT by serial number (more thorough search)
        
        Args:
            serial_number: Device serial number
            
        Returns:
            Asset dictionary or None if not found
        """
        try:
            # Try direct lookup first
            asset = self.find_asset_by_serial(serial_number)
            if asset:
                return asset
                
            # Then try search endpoint
            return self.check_serial_exists(serial_number)
            
        except Exception as e:
            logger.error(f"Error searching for asset by serial {serial_number}: {str(e)}")
            return None
    
    def create_model(self, name: str, category_id: str, manufacturer_id: str, model_number: str = '') -> Dict:
        """
        Create a new model in Snipe-IT
        
        Args:
            name: Model name
            category_id: Category ID
            manufacturer_id: Manufacturer ID
            model_number: Model number (optional)
            
        Returns:
            Response data
        """
        payload = {
            'name': name,
            'category_id': category_id,
            'manufacturer_id': manufacturer_id,
            'model_number': model_number or name
        }
        
        try:
            response = self._make_request('POST', 'api/v1/models', payload)
            return response.json()
        except Exception as e:
            logger.error(f"Error creating model {name}: {str(e)}")
            return {'status': 'error', 'messages': str(e)}
    
    def find_model_by_name(self, model_name: str) -> Optional[Dict]:
        """
        Find a model in Snipe-IT by name
        
        Args:
            model_name: Model name
            
        Returns:
            Model dictionary or None if not found
        """
        try:
            response = self._make_request('GET', f"api/v1/models?search={model_name}")
            data = response.json()
            
            if data.get('status') == 'error' or data.get('total', 0) == 0:
                return None
                
            # Look for exact match
            for model in data.get('rows', []):
                if model.get('name') == model_name:
                    return model
            
            # Fall back to first result if no exact match
            return data.get('rows', [])[0] if data.get('rows') else None
            
        except Exception as e:
            logger.error(f"Error finding model by name {model_name}: {str(e)}")
            return None
    
    def create_asset(self, asset_data: Dict) -> Dict:
        """
        Create a new asset in Snipe-IT
        
        Args:
            asset_data: Asset data
            
        Returns:
            Response data
        """
        try:
            response = self._make_request('POST', 'api/v1/hardware', asset_data)
            return response.json()
        except Exception as e:
            serial = asset_data.get('serial', 'Unknown')
            name = asset_data.get('name', 'Unknown')
            logger.error(f"Error creating asset for device (Serial: {serial}, Name: {name}): {str(e)}")
            return {'status': 'error', 'messages': str(e)}
    
    def update_asset(self, asset_id: int, asset_data: Dict) -> Dict:
        """
        Update an existing asset in Snipe-IT
        
        Args:
            asset_id: Asset ID
            asset_data: Asset data
            
        Returns:
            Response data
        """
        try:
            response = self._make_request('PUT', f"api/v1/hardware/{asset_id}", asset_data)
            return response.json()
        except Exception as e:
            serial = asset_data.get('serial', 'Unknown')
            name = asset_data.get('name', 'Unknown')
            logger.error(f"Error updating asset {asset_id} (Serial: {serial}, Name: {name}): {str(e)}")
            return {'status': 'error', 'messages': str(e)}
    
    def find_user_by_username(self, username: str) -> Optional[Dict]:
        """
        Find a user in Snipe-IT by username
        
        Args:
            username: Username
            
        Returns:
            User dictionary or None if not found
        """
        try:
            response = self._make_request('GET', f"api/v1/users?search={username}")
            data = response.json()
            
            if data.get('status') == 'error' or data.get('total', 0) == 0:
                return None
                
            # Look for exact match
            for user in data.get('rows', []):
                if user.get('username') == username:
                    return user
            
            # Fall back to first result if no exact match
            return data.get('rows', [])[0] if data.get('rows') else None
            
        except Exception as e:
            logger.error(f"Error finding user by username {username}: {str(e)}")
            return None


class MosyleSnipeSync:
    """Main class for syncing Mosyle devices to Snipe-IT"""
    
    def __init__(self, config_file: str = 'settings.json'):
        """Initialize sync with configuration file"""
        # Load configuration
        if not os.path.exists(config_file):
            logger.error(f"Configuration file {config_file} not found")
            raise FileNotFoundError(f"Configuration file {config_file} not found")
            
        try:
            with open(config_file, 'r') as f:
                self.config = json.load(f)
        except json.JSONDecodeError as e:
            logger.error(f"Error parsing JSON configuration file: {str(e)}")
            raise
        
        # Initialize API clients
        self.mosyle = MosyleAPI(self.config, config_file)
        self.snipeit = SnipeITAPI(self.config)
        
        # Statistics
        self.stats = {
            'total_devices': 0,
            'created': 0,
            'updated': 0,
            'models_updated': 0,
            'asset_tags_updated': 0,
            'purchase_dates_set': 0,
            'skipped': 0,
            'errors': 0
        }
    
    def _check_and_refresh_jwt_token(self, config_file: str):
        """
        Check if JWT token exists, if not and email/password/access_token are provided, get a new token
        
        Args:
            config_file: Path to configuration file to update with new token
        """
        mosyle_config = self.config.get('mosyle', {})
        
        # If JWT token is missing but we have email, password and access_token, get a new token
        if (not mosyle_config.get('jwt_token') and 
                mosyle_config.get('email') and 
                mosyle_config.get('password') and
                mosyle_config.get('access_token')):
            
            logger.info("JWT token not found in config but credentials are provided. Getting new token...")
            
            api_url = mosyle_config.get('api_url', 'https://managerapi.mosyle.com/v2')
            email = mosyle_config.get('email')
            password = mosyle_config.get('password')
            access_token = mosyle_config.get('access_token')
            
            # Get JWT token
            logger.info(f"Requesting JWT token from {api_url}")
            token = get_jwt_token(email, password, access_token, api_url)
            
            if token:
                logger.info("Successfully obtained new JWT token")
                
                # Update config in memory
                self.config['mosyle']['jwt_token'] = token
                
                # Update config file
                try:
                    with open(config_file, 'w') as f:
                        json.dump(self.config, f, indent=2)
                    logger.info(f"Updated JWT token in {config_file}")
                except Exception as e:
                    logger.error(f"Failed to update config file with new JWT token: {str(e)}")
            else:
                logger.error("Failed to get JWT token. Check your Mosyle credentials.")
                logger.error(f"Using parameters: email={email}, api_url={api_url}, access_token={access_token[:5]}...")
    
    def build_asset_payload(self, mosyle_device: Dict) -> Dict:
        """
        Build Snipe-IT asset payload from Mosyle device
        
        Args:
            mosyle_device: Device data from Mosyle
            
        Returns:
            Asset payload for Snipe-IT API
        """
        os_type = mosyle_device.get('os', '').lower()
        
        # Set category and custom field set based on OS type
        if os_type == 'mac':
            category_id = self.snipeit.macos_category_id
            fieldset_id = self.snipeit.macos_fieldset_id if self.snipeit.macos_fieldset_id else None
        elif os_type == 'ios':
            category_id = self.snipeit.ios_category_id
            fieldset_id = self.snipeit.ios_fieldset_id if self.snipeit.ios_fieldset_id else None
        elif os_type == 'tvos':
            category_id = self.snipeit.tvos_category_id
            fieldset_id = self.snipeit.tvos_fieldset_id if self.snipeit.tvos_fieldset_id else None
        else:
            category_id = self.snipeit.ios_category_id  # Default to iOS
            fieldset_id = None
        
        # Basic asset information
        payload = {
            'status_id': self.snipeit.default_status,
            'model_id': None,  # Will be set later
            'name': mosyle_device.get('device_name', ''),
            'serial': mosyle_device.get('serial_number', ''),
            'asset_tag': mosyle_device.get('asset_tag', '') or mosyle_device.get('serial_number', '')
        }
        
        # Handle first enroll date for purchase date (if available)
        first_enroll_date = mosyle_device.get('date_first_enrollment')
        if first_enroll_date:
            try:
                # Parse date from Mosyle format - might need adjustment based on actual format
                # Expected format: "07:14 PM - 08/05/2024"
                date_part = first_enroll_date.split(' - ')[1].strip()
                
                # Parse date to get month and year
                import datetime
                import re
                
                # Handle different date formats (MM/DD/YYYY or DD/MM/YYYY based on locale)
                # This assumes US format MM/DD/YYYY - adjust regex if needed
                match = re.search(r'(\d{1,2})/(\d{1,2})/(\d{4})', date_part)
                if match:
                    month, day, year = match.groups()
                    # Create date for first day of the month
                    purchase_date = datetime.date(int(year), int(month), 1)
                    payload['purchase_date'] = purchase_date.isoformat()
                    logger.info(f"Setting purchase date to {purchase_date} based on first enrollment date: {first_enroll_date}")
            except Exception as e:
                logger.warning(f"Failed to parse first enrollment date: {first_enroll_date}, error: {str(e)}")
        
        # Add custom fields if available
        custom_fields = {}
        
        # Only add custom fields that exist in Mosyle device data
        field_mappings = {
            'snipeit_os_version': 'osversion',
            'snipeit_imei': 'imei',
            'snipeit_mac_address': 'wifi_mac_address',
            'snipeit_model_name': 'model_name',
            'snipeit_last_checkin': 'date_last_beat',
            'snipeit_battery_level': 'battery',
            'snipeit_available_space': 'available_disk',
            'snipeit_total_disk': 'total_disk',
            'snipeit_supervised': 'is_supervised',
            'snipeit_ethernet_mac': 'ethernet_mac_address',
            'snipeit_bluetooth_mac': 'bluetooth_mac_address',
            'snipeit_activation_lock': 'isActivationLockEnabled',
            'snipeit_first_enrollment': 'date_first_enrollment'  # Add first enrollment date as a custom field
        }
        
        for snipeit_field, mosyle_field in field_mappings.items():
            if mosyle_field in mosyle_device and mosyle_device[mosyle_field] is not None:
                custom_fields[snipeit_field] = mosyle_device[mosyle_field]
        
        if custom_fields and fieldset_id:
            payload['custom_fields'] = custom_fields
        
        return payload
    
    def process_device(self, mosyle_device: Dict) -> bool:
        """
        Process a single device from Mosyle
        
        Args:
            mosyle_device: Device data from Mosyle
            
        Returns:
            Success status
        """
        # Skip user enrolled devices (BYOD)
        if mosyle_device.get('CurrentConsoleManagedUser') is None and mosyle_device.get('userid') is None:
            logger.info(f"Skipping user enrolled device (BYOD): {mosyle_device.get('device_name', 'Unknown')}")
            self.stats['skipped'] += 1
            return True
        
        # Skip devices without serial numbers
        serial_number = mosyle_device.get('serial_number')
        if not serial_number:
            logger.warning(f"Skipping device without serial number: {mosyle_device.get('device_name', 'Unknown')}")
            self.stats['skipped'] += 1
            return True
        
        device_name = mosyle_device.get('device_name', 'Unknown')
        logger.info(f"Processing device: {device_name} ({serial_number})")
        
        # Check if device already exists in Snipe-IT
        existing_asset = self.snipeit.find_asset_by_serial(serial_number)
        
        # Prepare asset payload
        payload = self.build_asset_payload(mosyle_device)
        
        # Handle model
        model_name = mosyle_device.get('device_model', '')
        if not model_name:
            logger.warning(f"Device missing model name: {serial_number}")
            model_name = "Unknown"
        
        # Find or create model
        model = self.snipeit.find_model_by_name(model_name)
        
        if not model:
            # Create new model
            os_type = mosyle_device.get('os', '').lower()
            if os_type == 'mac':
                category_id = self.snipeit.macos_category_id
            elif os_type == 'ios':
                category_id = self.snipeit.ios_category_id
            elif os_type == 'tvos':
                category_id = self.snipeit.tvos_category_id
            else:
                category_id = self.snipeit.ios_category_id  # Default
            
            logger.info(f"Creating new model: {model_name}")
            model_result = self.snipeit.create_model(
                name=model_name,
                category_id=category_id,
                manufacturer_id=self.snipeit.manufacturer_id,
                model_number=model_name
            )
            
            if model_result.get('status') == 'error':
                logger.error(f"Error creating model: {model_result.get('messages', 'Unknown error')}")
                self.stats['errors'] += 1
                return False
            
            model_id = model_result.get('payload', {}).get('id')
        else:
            model_id = model.get('id')
        
        # Set model ID in payload
        payload['model_id'] = model_id
        
        # Handle user assignment
        if mosyle_device.get('userid'):
            user = self.snipeit.find_user_by_username(mosyle_device['userid'])
            if user:
                # Include checkout information if user exists
                payload['assigned_user'] = user.get('id')
            else:
                logger.warning(f"User {mosyle_device['userid']} not found in Snipe-IT, asset will not be assigned")
        
        if existing_asset:
            # Update existing asset
            asset_id = existing_asset.get('id')
            
            # IMPORTANT: Do not modify the serial number when updating
            # This avoids "serial must be unique" errors
            if 'serial' in payload:
                existing_serial = existing_asset.get('serial')
                if existing_serial and existing_serial != payload['serial']:
                    logger.warning(f"Serial number mismatch for asset {asset_id}: Snipe-IT has '{existing_serial}', "
                                  f"Mosyle has '{payload['serial']}'. Keeping Snipe-IT serial to avoid conflicts.")
                del payload['serial']
            
            # Check if model differs between Mosyle and Snipe-IT
            existing_model_id = existing_asset.get('model', {}).get('id')
            existing_model_name = existing_asset.get('model', {}).get('name', 'Unknown')
            
            if existing_model_id and existing_model_id != model_id:
                logger.info(f"Model mismatch for {serial_number}: Snipe-IT has '{existing_model_name}' (ID: {existing_model_id}), Mosyle has '{model_name}' (ID: {model_id})")
                logger.info(f"Updating model to match Mosyle source of truth: {model_name}")
                # Model from Mosyle is used as source of truth
                payload['model_id'] = model_id
                self.stats['models_updated'] += 1
            
            # Check if asset tag differs between Mosyle and Snipe-IT
            existing_asset_tag = existing_asset.get('asset_tag')
            mosyle_asset_tag = mosyle_device.get('asset_tag') or mosyle_device.get('serial_number')
            
            if existing_asset_tag and mosyle_asset_tag and existing_asset_tag != mosyle_asset_tag:
                logger.info(f"Asset tag mismatch for {serial_number}: Snipe-IT has '{existing_asset_tag}', Mosyle has '{mosyle_asset_tag}'")
                logger.info(f"Updating asset tag to match Mosyle source of truth: {mosyle_asset_tag}")
                # Asset tag from Mosyle is used as source of truth
                payload['asset_tag'] = mosyle_asset_tag
                self.stats['asset_tags_updated'] = self.stats.get('asset_tags_updated', 0) + 1
            
            # Only set purchase_date if it doesn't already exist in Snipe-IT
            existing_purchase_date = existing_asset.get('purchase_date')
            if existing_purchase_date and 'purchase_date' in payload:
                logger.info(f"Keeping existing purchase date in Snipe-IT: {existing_purchase_date}")
                del payload['purchase_date']
            elif 'purchase_date' in payload:
                logger.info(f"Setting missing purchase date in Snipe-IT to: {payload['purchase_date']}")
                self.stats['purchase_dates_set'] = self.stats.get('purchase_dates_set', 0) + 1
            
            logger.info(f"Updating existing asset: {asset_id}")
            
            # Skip update if payload is empty after removing problematic fields
            if not payload:
                logger.info(f"No fields to update for asset {asset_id}, skipping update")
                return True
            
            result = self.snipeit.update_asset(asset_id, payload)
            
            if result.get('status') == 'success':
                logger.info(f"Successfully updated asset: {asset_id}")
                self.stats['updated'] += 1
                return True
            else:
                error_msg = result.get('messages', 'Unknown error')
                if isinstance(error_msg, dict) and 'serial' in error_msg and 'unique' in str(error_msg['serial']):
                    # Handle serial number conflict
                    logger.warning(f"Serial number conflict for asset {asset_id}. "
                                  f"Serial '{serial_number}' is already assigned to another asset. "
                                  f"Removing serial from update payload and retrying.")
                    
                    # Remove serial from payload and retry
                    if 'serial' in payload:
                        del payload['serial']
                    
                    if payload:  # Only retry if there are other fields to update
                        retry_result = self.snipeit.update_asset(asset_id, payload)
                        if retry_result.get('status') == 'success':
                            logger.info(f"Successfully updated asset {asset_id} after removing serial from payload")
                            self.stats['updated'] += 1
                            return True
                        else:
                            logger.error(f"Error updating asset {asset_id} even after removing serial: {retry_result.get('messages', 'Unknown error')}")
                            self.stats['errors'] += 1
                            return False
                    else:
                        logger.info(f"No fields to update for asset {asset_id} after removing serial, skipping update")
                        return True
                else:
                    logger.error(f"Error updating asset {asset_id}: {error_msg}")
                    self.stats['errors'] += 1
                    return False
        else:
            # Create new asset
            logger.info(f"Creating new asset for device: {serial_number}")
            
            # Check if serial already exists but wasn't found by direct lookup
            # This can happen if there are case sensitivity issues
            check_serial = self.snipeit.check_serial_exists(serial_number)
            if check_serial:
                logger.warning(f"Serial number {serial_number} exists in Snipe-IT but with different casing or formatting. "
                               f"Found asset ID: {check_serial.get('id')}. "
                               f"Will update instead of creating.")
                return self.process_device_as_update(mosyle_device, check_serial)
            
            result = self.snipeit.create_asset(payload)
            
            if result.get('status') == 'success':
                logger.info(f"Successfully created asset: {result.get('payload', {}).get('id')}")
                self.stats['created'] += 1
                return True
            else:
                error_msg = result.get('messages', 'Unknown error')
                if isinstance(error_msg, dict) and 'serial' in error_msg and 'unique' in str(error_msg['serial']):
                    # The serial number is already in use, try to find the asset
                    logger.warning(f"Serial number conflict when creating asset for {serial_number}. "
                                  f"Searching for existing asset to update instead.")
                    
                    # Search for the asset with this serial (case-insensitive search)
                    found_asset = self.snipeit.search_asset_by_serial(serial_number)
                    if found_asset:
                        logger.info(f"Found existing asset with serial {serial_number} (ID: {found_asset.get('id')}). "
                                   f"Will update instead of creating.")
                        return self.process_device_as_update(mosyle_device, found_asset)
                    else:
                        logger.error(f"Could not create asset due to serial number conflict, "
                                    f"but couldn't find the conflicting asset. "
                                    f"Manual intervention required for {serial_number}.")
                        self.stats['errors'] += 1
                        return False
                else:
                    logger.error(f"Error creating asset: {error_msg}")
                    self.stats['errors'] += 1
                    return False
    
    def process_device_as_update(self, mosyle_device: Dict, existing_asset: Dict) -> bool:
        """
        Process a device as an update when it was initially tried as a create
        
        Args:
            mosyle_device: Device data from Mosyle
            existing_asset: Existing asset in Snipe-IT
            
        Returns:
            Success status
        """
        # This is a simplified version of the update logic from process_device
        asset_id = existing_asset.get('id')
        logger.info(f"Processing device as update: {mosyle_device.get('device_name', 'Unknown')} "
                   f"({mosyle_device.get('serial_number', 'Unknown')}) -> Asset ID: {asset_id}")
        
        # Prepare asset payload without serial
        payload = self.build_asset_payload(mosyle_device)
        if 'serial' in payload:
            del payload['serial']  # Never update serial when doing this fallback update
        
        if not payload:
            logger.info(f"No fields to update for asset {asset_id}, skipping update")
            return True
            
        result = self.snipeit.update_asset(asset_id, payload)
        
        if result.get('status') == 'success':
            logger.info(f"Successfully updated asset as fallback: {asset_id}")
            self.stats['updated'] += 1
            return True
        else:
            logger.error(f"Error updating asset {asset_id} as fallback: {result.get('messages', 'Unknown error')}")
            self.stats['errors'] += 1
            return False
    
    def run(self, device_type: str = 'all', dry_run: bool = False, batch_size: int = 50, batch_delay: float = 5.0):
        """
        Run the sync process
        
        Args:
            device_type: Type of devices to sync (ios, mac, tvos)
            dry_run: If True, don't actually create/update assets
            batch_size: Number of devices to process in each batch
            batch_delay: Delay in seconds between batches
        """
        logger.info(f"Starting Mosyle to Snipe-IT sync (device_type: {device_type}, dry_run: {dry_run}, "
                    f"batch_size: {batch_size}, batch_delay: {batch_delay})")
        
        # Get devices from Mosyle
        devices = self.mosyle.get_devices(device_type)
        
        if not devices:
            logger.warning("No devices found in Mosyle")
            return
        
        self.stats['total_devices'] = len(devices)
        logger.info(f"Found {len(devices)} devices in Mosyle")
        
        if dry_run:
            logger.info("DRY RUN MODE - No changes will be made to Snipe-IT")
            
            # Just print summary of what would be done
            for device in devices:
                serial = device.get('serial_number', 'Unknown')
                name = device.get('device_name', 'Unknown')
                existing_asset = self.snipeit.find_asset_by_serial(serial) if serial != 'Unknown' else None
                
                if existing_asset:
                    logger.info(f"Would update: {name} ({serial})")
                else:
                    logger.info(f"Would create: {name} ({serial})")
        else:
            # Process devices in batches to reduce load on Snipe-IT API
            total_batches = (len(devices) + batch_size - 1) // batch_size  # Ceiling division
            
            for batch_index in range(total_batches):
                start_idx = batch_index * batch_size
                end_idx = min(start_idx + batch_size, len(devices))
                batch_devices = devices[start_idx:end_idx]
                
                logger.info(f"Processing batch {batch_index + 1}/{total_batches} "
                            f"(devices {start_idx + 1}-{end_idx} of {len(devices)})")
                
                # Process each device in the batch
                for device in batch_devices:
                    self.process_device(device)
                
                # Pause between batches to reduce API load (except after the last batch)
                if batch_index < total_batches - 1 and batch_delay > 0:
                    logger.info(f"Batch {batch_index + 1} complete. Pausing for {batch_delay} seconds before next batch...")
                    time.sleep(batch_delay)
        
        # Print statistics
        logger.info("Sync completed with the following results:")
        logger.info(f"  Total devices: {self.stats['total_devices']}")
        logger.info(f"  Created: {self.stats['created']}")
        logger.info(f"  Updated: {self.stats['updated']}")
        logger.info(f"  Models updated: {self.stats['models_updated']}")
        logger.info(f"  Asset tags updated: {self.stats['asset_tags_updated']}")
        logger.info(f"  Purchase dates set: {self.stats['purchase_dates_set']}")
        logger.info(f"  Skipped: {self.stats['skipped']}")
        logger.info(f"  Errors: {self.stats['errors']}")


def sync_command(args: argparse.Namespace) -> None:
    """
    Handle the sync command
    
    Args:
        args: Command line arguments
    """
    try:
        sync = MosyleSnipeSync(args.config)
        sync.run(args.device_type, args.dry_run, args.batch_size, args.batch_delay)
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        sys.exit(1)


def main():
    """Main function"""
    # Create parent parser with common arguments
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument('--config', dest='config', default='settings.json',
                        help='Path to configuration file (default: settings.json)')
    
    # Create main parser
    parser = argparse.ArgumentParser(description='Mosyle to Snipe-IT Sync Tool')
    subparsers = parser.add_subparsers(dest='command', help='Command to run')
    
    # Token command
    token_parser = subparsers.add_parser('token', parents=[parent_parser],
                                        help='Generate JWT token for Mosyle API')
    token_parser.add_argument('--api-url', help='Mosyle API URL (if different than in config)')
    
    # Sync command
    sync_parser = subparsers.add_parser('sync', parents=[parent_parser],
                                       help='Sync devices from Mosyle to Snipe-IT')
    sync_parser.add_argument('--device-type', dest='device_type', default='all',
                            choices=['all', 'ios', 'mac', 'tvos'],
                            help='Type of devices to sync (default: all)')
    sync_parser.add_argument('--dry-run', dest='dry_run', action='store_true',
                            help='Dry run (do not make changes to Snipe-IT)')
    sync_parser.add_argument('--batch-size', dest='batch_size', type=int, default=50,
                            help='Number of devices to process in each batch (default: 50)')
    sync_parser.add_argument('--batch-delay', dest='batch_delay', type=float, default=5.0,
                            help='Delay in seconds between batches (default: 5.0)')
    
    # For backward compatibility, make sync the default command if no command is specified
    args = parser.parse_args()
    
    if args.command is None or args.command == 'sync':
        # If no command specified or 'sync' command specified, run sync
        if args.command is None:
            # Handle case where no command was specified, use default values for sync
            args.device_type = 'all'
            args.dry_run = False
            args.batch_size = 50
            args.batch_delay = 5.0
        sync_command(args)
    elif args.command == 'token':
        token_command(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()