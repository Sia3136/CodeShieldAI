"""
GitHub OAuth Authentication Module
Handles GitHub OAuth flow, token management, and user authentication.
"""
import os
import secrets
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from github import Github, GithubException
from cryptography.fernet import Fernet
from dotenv import load_dotenv

load_dotenv()

# GitHub OAuth Configuration
GITHUB_CLIENT_ID = os.getenv("GITHUB_CLIENT_ID")
GITHUB_CLIENT_SECRET = os.getenv("GITHUB_CLIENT_SECRET")
GITHUB_REDIRECT_URI = os.getenv("GITHUB_REDIRECT_URI", "http://localhost:5173/auth/callback")

# Encryption key for token storage (generate once and store securely)
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY")
if not ENCRYPTION_KEY:
    ENCRYPTION_KEY = Fernet.generate_key().decode()
    print("[WARNING] No ENCRYPTION_KEY in .env, generated temporary key")

cipher = Fernet(ENCRYPTION_KEY.encode() if isinstance(ENCRYPTION_KEY, str) else ENCRYPTION_KEY)


class GitHubAuthError(Exception):
    """Custom exception for GitHub authentication errors"""
    pass


def generate_oauth_url(state: Optional[str] = None) -> Dict[str, str]:
    """
    Generate GitHub OAuth authorization URL.
    
    Args:
        state: Optional CSRF protection state parameter
        
    Returns:
        Dictionary with 'url' and 'state'
    """
    if not GITHUB_CLIENT_ID:
        raise GitHubAuthError("GITHUB_CLIENT_ID not configured")
    
    if not state:
        state = secrets.token_urlsafe(32)
    
    scopes = "repo,read:user,user:email"  # Adjust scopes as needed
    auth_url = (
        f"https://github.com/login/oauth/authorize"
        f"?client_id={GITHUB_CLIENT_ID}"
        f"&redirect_uri={GITHUB_REDIRECT_URI}"
        f"&scope={scopes}"
        f"&state={state}"
    )
    
    return {
        "url": auth_url,
        "state": state
    }


def exchange_code_for_token(code: str) -> Dict[str, Any]:
    """
    Exchange OAuth code for access token.
    
    Args:
        code: OAuth authorization code from callback
        
    Returns:
        Dictionary with token information and user data
    """
    import requests
    
    if not GITHUB_CLIENT_ID or not GITHUB_CLIENT_SECRET:
        raise GitHubAuthError("GitHub OAuth credentials not configured")
    
    # Exchange code for token
    token_url = "https://github.com/login/oauth/access_token"
    headers = {"Accept": "application/json"}
    data = {
        "client_id": GITHUB_CLIENT_ID,
        "client_secret": GITHUB_CLIENT_SECRET,
        "code": code,
        "redirect_uri": GITHUB_REDIRECT_URI
    }
    
    try:
        response = requests.post(token_url, headers=headers, data=data, timeout=10)
        response.raise_for_status()
        token_data = response.json()
        
        if "error" in token_data:
            raise GitHubAuthError(f"OAuth error: {token_data.get('error_description', 'Unknown error')}")
        
        access_token = token_data.get("access_token")
        if not access_token:
            raise GitHubAuthError("No access token received")
        
        # Get user information
        gh = Github(access_token)
        user = gh.get_user()
        
        return {
            "access_token": access_token,
            "token_type": token_data.get("token_type", "bearer"),
            "scope": token_data.get("scope", ""),
            "user": {
                "id": user.id,
                "login": user.login,
                "name": user.name,
                "email": user.email,
                "avatar_url": user.avatar_url,
                "html_url": user.html_url
            },
            "created_at": datetime.utcnow().isoformat()
        }
        
    except requests.RequestException as e:
        raise GitHubAuthError(f"Failed to exchange code for token: {str(e)}")
    except GithubException as e:
        raise GitHubAuthError(f"Failed to fetch user data: {str(e)}")


def encrypt_token(token: str) -> str:
    """Encrypt access token for secure storage"""
    return cipher.encrypt(token.encode()).decode()


def decrypt_token(encrypted_token: str) -> str:
    """Decrypt access token from storage"""
    return cipher.decrypt(encrypted_token.encode()).decode()


def validate_token(access_token: str) -> bool:
    """
    Validate GitHub access token.
    
    Args:
        access_token: GitHub access token
        
    Returns:
        True if token is valid, False otherwise
    """
    try:
        gh = Github(access_token)
        gh.get_user().login  # Test API call
        return True
    except GithubException:
        return False


def get_user_repositories(access_token: str, visibility: str = "all") -> list:
    """
    Get user's GitHub repositories.
    
    Args:
        access_token: GitHub access token
        visibility: Repository visibility filter ("all", "public", "private")
        
    Returns:
        List of repository dictionaries
    """
    try:
        gh = Github(access_token)
        user = gh.get_user()
        repos = user.get_repos(visibility=visibility)
        
        return [
            {
                "id": repo.id,
                "name": repo.name,
                "full_name": repo.full_name,
                "description": repo.description,
                "html_url": repo.html_url,
                "clone_url": repo.clone_url,
                "default_branch": repo.default_branch,
                "language": repo.language,
                "private": repo.private,
                "updated_at": repo.updated_at.isoformat() if repo.updated_at else None
            }
            for repo in repos
        ]
    except GithubException as e:
        raise GitHubAuthError(f"Failed to fetch repositories: {str(e)}")


def get_repository_branches(access_token: str, repo_full_name: str) -> list:
    """
    Get branches for a specific repository.
    
    Args:
        access_token: GitHub access token
        repo_full_name: Repository full name (owner/repo)
        
    Returns:
        List of branch names
    """
    try:
        gh = Github(access_token)
        repo = gh.get_repo(repo_full_name)
        branches = repo.get_branches()
        
        return [
            {
                "name": branch.name,
                "commit_sha": branch.commit.sha,
                "protected": branch.protected
            }
            for branch in branches
        ]
    except GithubException as e:
        raise GitHubAuthError(f"Failed to fetch branches: {str(e)}")
