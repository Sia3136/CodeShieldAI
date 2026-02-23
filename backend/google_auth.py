"""
Google OAuth Authentication Module
Handles Google OAuth 2.0 flow for user authentication
"""

import os
import requests
from typing import Dict
from dotenv import load_dotenv

load_dotenv()

# Google OAuth Configuration
GOOGLE_CLIENT_ID = os.getenv("GOOGLE_CLIENT_ID")
GOOGLE_CLIENT_SECRET = os.getenv("GOOGLE_CLIENT_SECRET")
GOOGLE_REDIRECT_URI = os.getenv("GOOGLE_REDIRECT_URI", "http://localhost:8000/auth/google/callback")

# Google OAuth URLs
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"


class GoogleAuthError(Exception):
    """Custom exception for Google OAuth errors"""
    pass


def generate_google_oauth_url() -> Dict[str, str]:
    """
    Generate Google OAuth authorization URL
    
    Returns:
        Dict with 'url' key containing the authorization URL
    """
    if not GOOGLE_CLIENT_ID:
        raise GoogleAuthError("GOOGLE_CLIENT_ID not configured")
    
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "response_type": "code",
        "scope": "openid email profile",
        "access_type": "offline",
        "prompt": "consent"
    }
    
    # Build URL with parameters
    param_string = "&".join([f"{k}={v}" for k, v in params.items()])
    auth_url = f"{GOOGLE_AUTH_URL}?{param_string}"
    
    return {"url": auth_url}


def exchange_code_for_token(code: str) -> Dict[str, any]:
    """
    Exchange authorization code for access token and user info
    
    Args:
        code: Authorization code from Google OAuth callback
        
    Returns:
        Dict containing access_token and user information
    """
    if not all([GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET]):
        raise GoogleAuthError("Google OAuth credentials not configured")
    
    # Exchange code for token
    token_data = {
        "code": code,
        "client_id": GOOGLE_CLIENT_ID,
        "client_secret": GOOGLE_CLIENT_SECRET,
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "grant_type": "authorization_code"
    }
    
    try:
        # Get access token
        token_response = requests.post(GOOGLE_TOKEN_URL, data=token_data, timeout=10)
        token_response.raise_for_status()
        token_json = token_response.json()
        
        access_token = token_json.get("access_token")
        if not access_token:
            raise GoogleAuthError("No access token in response")
        
        # Get user info
        headers = {"Authorization": f"Bearer {access_token}"}
        user_response = requests.get(GOOGLE_USERINFO_URL, headers=headers, timeout=10)
        user_response.raise_for_status()
        user_info = user_response.json()
        
        return {
            "access_token": access_token,
            "user": {
                "id": user_info.get("id"),
                "email": user_info.get("email"),
                "name": user_info.get("name"),
                "picture": user_info.get("picture"),
                "verified_email": user_info.get("verified_email", False)
            }
        }
        
    except requests.exceptions.RequestException as e:
        raise GoogleAuthError(f"Failed to exchange code for token: {str(e)}")
    except Exception as e:
        raise GoogleAuthError(f"Google OAuth error: {str(e)}")


def validate_google_token(access_token: str) -> bool:
    """
    Validate a Google access token
    
    Args:
        access_token: Google OAuth access token
        
    Returns:
        True if token is valid, False otherwise
    """
    try:
        headers = {"Authorization": f"Bearer {access_token}"}
        response = requests.get(GOOGLE_USERINFO_URL, headers=headers, timeout=10)
        return response.status_code == 200
    except:
        return False
