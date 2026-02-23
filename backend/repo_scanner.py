"""
Repository Scanner Module
Handles cloning, scanning, and analyzing GitHub repositories for vulnerabilities.
"""
import os
import shutil
import tempfile
from typing import List, Dict, Any, Optional
from pathlib import Path
import git
from git import Repo, GitCommandError
import fnmatch
from datetime import datetime


class RepositoryScannerError(Exception):
    """Custom exception for repository scanning errors"""
    pass


class RepositoryScanner:
    """Handles repository cloning and file scanning"""
    
    def __init__(self, temp_dir: Optional[str] = None):
        """
        Initialize repository scanner.
        
        Args:
            temp_dir: Optional temporary directory for cloning repos
        """
        self.temp_dir = temp_dir or tempfile.gettempdir()
        self.clone_path = None
    
    def clone_repository(
        self,
        repo_url: str,
        branch: str = "main",
        depth: int = 1,
        access_token: Optional[str] = None
    ) -> str:
        """
        Clone a GitHub repository.
        
        Args:
            repo_url: Repository URL (https://github.com/owner/repo)
            branch: Branch to clone
            depth: Clone depth (1 for shallow clone)
            access_token: Optional GitHub access token for private repos
            
        Returns:
            Path to cloned repository
        """
        try:
            # Create unique directory for this clone
            repo_name = repo_url.rstrip('/').split('/')[-1].replace('.git', '')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            clone_dir = os.path.join(self.temp_dir, f"codeshield_{repo_name}_{timestamp}")
            
            # Inject access token for private repos
            if access_token and repo_url.startswith('https://'):
                repo_url = repo_url.replace('https://', f'https://{access_token}@')
            
            print(f"[CLONE] Cloning {repo_url} (branch: {branch}, depth: {depth})")
            
            # Clone repository
            Repo.clone_from(
                repo_url,
                clone_dir,
                branch=branch,
                depth=depth,
                single_branch=True
            )
            
            self.clone_path = clone_dir
            print(f"[CLONE] Successfully cloned to {clone_dir}")
            return clone_dir
            
        except GitCommandError as e:
            raise RepositoryScannerError(f"Failed to clone repository: {str(e)}")
        except Exception as e:
            raise RepositoryScannerError(f"Unexpected error during clone: {str(e)}")
    
    def get_files_by_pattern(
        self,
        clone_path: str,
        patterns: List[str] = None,
        exclude_patterns: List[str] = None,
        max_files: int = 500
    ) -> List[Dict[str, Any]]:
        """
        Get files from cloned repository matching patterns.
        
        Args:
            clone_path: Path to cloned repository
            patterns: List of file patterns to include (e.g., ['*.py', '*.js'])
            exclude_patterns: List of patterns to exclude (e.g., ['*test*', '*.min.js'])
            max_files: Maximum number of files to return
            
        Returns:
            List of file dictionaries with path and metadata
        """
        if patterns is None:
            patterns = ['*.py', '*.js', '*.ts', '*.jsx', '*.tsx', '*.java', '*.php', '*.rb', '*.go', '*.ipynb', '*.c', '*.cpp', '*.h', '*.hpp', '*.cs', '*.sh']
        
        if exclude_patterns is None:
            exclude_patterns = [
                '*test*', '*Test*', '*spec*', '*.min.js', '*.min.css',
                'node_modules/*', '.git/*', 'venv/*', '__pycache__/*',
                'dist/*', 'build/*', '.next/*', 'coverage/*'
            ]
        
        files = []
        repo_path = Path(clone_path)
        
        try:
            for file_path in repo_path.rglob('*'):
                if not file_path.is_file():
                    continue
                
                relative_path = file_path.relative_to(repo_path)
                relative_str = relative_path.as_posix() # Normalize to forward slashes for matching
                
                # Check exclude patterns
                if any(fnmatch.fnmatch(relative_str, pattern) for pattern in exclude_patterns):
                    continue
                
                # Check include patterns
                if any(fnmatch.fnmatch(relative_str, pattern) for pattern in patterns):
                    files.append({
                        'path': relative_str,
                        'absolute_path': str(file_path),
                        'size': file_path.stat().st_size,
                        'extension': file_path.suffix
                    })
                    
                    if len(files) >= max_files:
                        print(f"[SCAN] Reached max file limit ({max_files})")
                        break
            
            print(f"[SCAN] Found {len(files)} files matching patterns")
            return files
            
        except Exception as e:
            raise RepositoryScannerError(f"Failed to scan files: {str(e)}")
    
    def read_file_content(self, file_path: str, max_size: int = 1024 * 1024) -> Optional[str]:
        """
        Read file content safely.
        
        Args:
            file_path: Absolute path to file
            max_size: Maximum file size to read (default 1MB)
            
        Returns:
            File content as string, or None if file is too large or binary
        """
        try:
            file_size = os.path.getsize(file_path)
            if file_size > max_size:
                print(f"[SCAN] Skipping large file: {file_path} ({file_size} bytes)")
                return None
            
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                return f.read()
                
        except Exception as e:
            print(f"[SCAN] Failed to read {file_path}: {str(e)}")
            return None
    
    def cleanup(self):
        """Remove cloned repository directory"""
        if self.clone_path and os.path.exists(self.clone_path):
            try:
                shutil.rmtree(self.clone_path)
                print(f"[CLEANUP] Removed {self.clone_path}")
                self.clone_path = None
            except Exception as e:
                print(f"[CLEANUP] Failed to remove {self.clone_path}: {str(e)}")
    
    def __enter__(self):
        """Context manager entry"""
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit - cleanup automatically"""
        self.cleanup()


def parse_github_url(repo_url: str) -> Dict[str, str]:
    """
    Parse GitHub repository URL.
    
    Args:
        repo_url: GitHub repository URL
        
    Returns:
        Dictionary with owner, repo, and full_name
        
    Examples:
        >>> parse_github_url("https://github.com/owner/repo")
        {'owner': 'owner', 'repo': 'repo', 'full_name': 'owner/repo'}
    """
    # Remove .git suffix if present
    repo_url = repo_url.rstrip('/').replace('.git', '')
    
    # Extract owner and repo from URL
    parts = repo_url.split('/')
    if len(parts) < 2:
        raise RepositoryScannerError(f"Invalid GitHub URL: {repo_url}")
    
    repo = parts[-1]
    owner = parts[-2]
    
    return {
        'owner': owner,
        'repo': repo,
        'full_name': f"{owner}/{repo}"
    }
