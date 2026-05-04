#!/usr/bin/env python3
import os
import csv
import io
import time
import datetime
import logging
import subprocess
import json
import platform
import getpass
import base64
import socket
import tempfile
from pathlib import Path

# Add python-dotenv for environment variable management
try:
    from dotenv import load_dotenv
except ImportError:
    # If dotenv is not installed, we'll define a simple version
    def load_dotenv(path=None):
        """Simple .env file loader when python-dotenv is not available."""
        if not path:
            path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
        
        if not os.path.exists(path):
            logging.warning(f".env file not found at {path}")
            return False
            
        with open(path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    key, value = line.split('=', 1)
                    os.environ[key.strip()] = value.strip().strip('"\'')
        return True

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Load environment variables from .env file
env_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
load_dotenv(env_file)

# GitHub API configuration
GITHUB_API_BASE = "https://api.github.com"

# Get configuration from environment variables with fallbacks
TRACKING_REPO_OWNER = os.environ.get("TRACKING_REPO_OWNER", "your-org-name")
TRACKING_REPO_NAME = os.environ.get("TRACKING_REPO_NAME", "installation-tracking")
CSV_PATH = os.environ.get("TRACKING_CSV_PATH", "installations.csv")

def run_subprocess(cmd, **kwargs):
    """Run a subprocess command with appropriate flags to hide console window on Windows."""
    if platform.system().lower() == 'windows':
        # Add CREATE_NO_WINDOW flag on Windows to prevent console window from appearing
        kwargs['creationflags'] = subprocess.CREATE_NO_WINDOW
    
    return subprocess.run(cmd, **kwargs)

def get_git_email():
    """Get the email from Git configuration."""
    try:
        # Try to get user.email from git config
        result = run_subprocess(
            ['git', 'config', 'user.email'],
            capture_output=True,
            text=True,
            check=False
        )
        email = result.stdout.strip()
        
        if email:
            return email
        
        # If no email found, return a placeholder
        return "no-email-configured"
    except Exception as e:
        logging.warning(f"Error getting email from git config: {e}")
        return "git-config-error"

def get_username():
    """Get the username from whoami command, removing 'heap/' prefix if it exists."""
    try:
        # Run the whoami command to get system username
        result = run_subprocess(
            ['whoami'],
            capture_output=True,
            text=True,
            check=False
        )
        username = result.stdout.strip()
        
        # If username contains "heap/", remove that prefix
        if '/' in username and username.lower().startswith('heap/'):
            username = username.split('/', 1)[1]
        
        if username:
            return username
    except Exception as e:
        logging.warning(f"Error getting username from whoami: {e}")
    
    # If all else fails, get the system username
    return getpass.getuser()

def get_user_info():
    """Get current user information for tracking."""
    try:
        # Get username from whoami command
        username = get_username()
        # Get email from git config
        email = get_git_email()
        hostname = socket.gethostname()
        os_info = f"{platform.system()} {platform.release()}"
        return {
            "user": username,
            "email": email,
            "hostname": hostname,
            "os": os_info
        }
    except Exception as e:
        logging.error(f"Error getting user info: {e}")
        return {"user": "unknown", "email": "unknown", "hostname": "unknown", "os": "unknown"}

def get_github_token():
    """Get GitHub token from environment variables."""
    # Try to get token from GITHUB_TOKEN env var first (for backward compatibility)
    token = os.environ.get('GITHUB_TOKEN')
    
    # If not found, try GITHUB_PAT which is the recommended name for the token
    if not token:
        token = os.environ.get('GITHUB_PAT')
    
    if not token:
        logging.warning("No GitHub token found. Set GITHUB_PAT in your .env file.")
        
    return token

def fetch_csv_from_github():
    """Fetch the installations CSV from the external GitHub repository using curl."""
    token = get_github_token()
    if not token:
        return None, None
    
    url = f"{GITHUB_API_BASE}/repos/{TRACKING_REPO_OWNER}/{TRACKING_REPO_NAME}/contents/{CSV_PATH}"
    
    try:
        # Prepare curl command
        curl_command = [
            "curl",
            "-s",  # silent
            "-H", "Accept: application/vnd.github.v3+json",
            "-H", f"Authorization: token {token}",
            url
        ]

        # Execute curl command using our wrapper function
        result = run_subprocess(curl_command, capture_output=True, text=True)
        
        if result.returncode == 0:
            # Try to parse the JSON response
            try:
                response_json = json.loads(result.stdout)
                
                # Check if we have content
                if "content" in response_json:
                    content_encoded = response_json["content"]
                    content = base64.b64decode(content_encoded).decode('utf-8')
                    sha = response_json.get("sha")
                    return content, sha
                else:
                    # Did we get an error?
                    if "message" in response_json:
                        if response_json.get("message") == "Not Found":
                            logging.info(f"CSV file not found in tracking repository. It will be created.")
                            return "", None
                        else:
                            logging.error(f"GitHub API error: {response_json.get('message')}")
                            return None, None
            except json.JSONDecodeError:
                logging.error(f"Failed to parse JSON response from GitHub API")
                return None, None
        else:
            logging.error(f"Curl command failed: {result.stderr}")
            return None, None
    except Exception as e:
        logging.error(f"Error fetching CSV from GitHub with curl: {e}")
        return None, None

def parse_csv_data(csv_content):
    """Parse CSV content into a list of dictionaries."""
    if not csv_content:
        # Return empty list with headers for a new file
        return []
    
    try:
        reader = csv.DictReader(io.StringIO(csv_content))
        return list(reader)
    except Exception as e:
        logging.error(f"Error parsing CSV data: {e}")
        return []

def csv_to_string(data):
    """Convert CSV data to a string."""
    output = io.StringIO()
    
    if not data:
        # Just write headers for empty data with email field added
        writer = csv.writer(output)
        writer.writerow(['user', 'email', 'timestamp', 'status', 'hostname', 'os'])
    else:
        # Check if we need to add the email field to existing data
        if 'email' not in data[0]:
            for entry in data:
                entry['email'] = "unknown"
                
        # Write headers and data rows
        writer = csv.DictWriter(output, fieldnames=data[0].keys())
        writer.writeheader()
        writer.writerows(data)
        
    return output.getvalue()

def update_csv_in_github(csv_content, file_sha, commit_message):
    """Update the CSV file in the GitHub repository using curl."""
    token = get_github_token()
    if not token:
        return False
    
    url = f"{GITHUB_API_BASE}/repos/{TRACKING_REPO_OWNER}/{TRACKING_REPO_NAME}/contents/{CSV_PATH}"
    
    # Encode content for GitHub API
    content_encoded = base64.b64encode(csv_content.encode('utf-8')).decode('utf-8')
    
    # Create JSON payload
    if file_sha:
        # Update existing file
        payload = {
            'message': commit_message,
            'content': content_encoded,
            'sha': file_sha
        }
    else:
        # Create new file
        payload = {
            'message': commit_message,
            'content': content_encoded
        }
    
    # Convert payload to JSON string
    payload_json = json.dumps(payload)
    
    try:
        # Create a temporary file to store the JSON payload
        with tempfile.NamedTemporaryFile(mode='w+', suffix='.json', delete=False) as temp_file:
            temp_file_path = temp_file.name
            temp_file.write(payload_json)
        
        try:
            # Prepare curl command to use the temporary file
            curl_command = [
                "curl",
                "-s",  # silent
                "-X", "PUT",
                "-H", "Accept: application/vnd.github.v3+json",
                "-H", f"Authorization: token {token}",
                "-H", "Content-Type: application/json",
                "--data-binary", f"@{temp_file_path}",  # Use the temp file instead of inline data
                url
            ]

            # Execute curl command using our wrapper function
            result = run_subprocess(curl_command, capture_output=True, text=True)
            
            if result.returncode == 0:
                try:
                    response_json = json.loads(result.stdout)
                    if "content" in response_json:
                        logging.info(f"Successfully updated CSV in GitHub: {commit_message}")
                        return True
                    else:
                        # Check for error message
                        if "message" in response_json:
                            logging.error(f"GitHub API error: {response_json.get('message')}")
                        else:
                            logging.error("Unknown error while updating CSV in GitHub")
                        return False
                except json.JSONDecodeError:
                    logging.error(f"Failed to parse JSON response from GitHub API")
                    return False
            else:
                logging.error(f"Curl command failed: {result.stderr}")
                return False
        finally:
            # Clean up the temporary file
            try:
                os.unlink(temp_file_path)
            except Exception as e:
                logging.warning(f"Failed to delete temporary file {temp_file_path}: {e}")
    except Exception as e:
        logging.error(f"Error updating CSV in GitHub with curl: {e}")
        return False

def update_installation_status(status):
    """Update installation status in the external tracking repository.
    
    Args:
        status (str): Either 'installed' or 'uninstalled'
    """
    user_info = get_user_info()
    username = user_info['user']
    email = user_info['email']
    now = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # Fetch current CSV content from GitHub
    csv_content, file_sha = fetch_csv_from_github()
    if csv_content is None:  # Error occurred
        logging.error("Failed to fetch tracking data from GitHub")
        return False
    
    # Parse CSV data
    data = parse_csv_data(csv_content)
    
    # Check if user already exists
    user_found = False
    for entry in data:
        if entry['user'] == username:
            # Update existing record
            entry['timestamp'] = now
            entry['status'] = status
            entry['email'] = email  # Update email in case it changed
            entry['hostname'] = user_info['hostname']
            entry['os'] = user_info['os']
            user_found = True
            break
    
    # If user not found, add new record
    if not user_found:
        if not data:
            # Create the first record with proper headers
            data = [{
                'user': username,
                'email': email,
                'timestamp': now,
                'status': status,
                'hostname': user_info['hostname'],
                'os': user_info['os']
            }]
        else:
            # Make sure existing data has the email field
            if 'email' not in data[0]:
                for entry in data:
                    entry['email'] = "unknown"
                    
            # Add new record
            data.append({
                'user': username,
                'email': email,
                'timestamp': now,
                'status': status,
                'hostname': user_info['hostname'],
                'os': user_info['os']
            })
    
    # Convert data back to CSV string
    updated_csv = csv_to_string(data)
    
    # Update CSV in GitHub
    commit_msg = f"Update installation status: {username} {status}"
    return update_csv_in_github(updated_csv, file_sha, commit_msg)

def record_installation():
    """Record that a user has installed the hooks."""
    return update_installation_status('installed')

def record_uninstallation():
    """Record that a user has uninstalled the hooks."""
    return update_installation_status('uninstalled') 