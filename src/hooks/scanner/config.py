"""Configuration settings for secret scanning."""

import os
import sys
from typing import List, Tuple, Dict, Set
import fnmatch

# Ensure the current directory is in the path for imports
script_dir = os.path.dirname(os.path.abspath(__file__))
if script_dir not in sys.path:
    sys.path.append(script_dir)

# Import scan_config if available
try:
    from scan_config import get_exclusion_patterns, load_exclusions
except ImportError:
    # Fallback functions if scan_config is not available
    def get_exclusion_patterns():
        return []
    
    def load_exclusions():
        return {
            "file_extensions": [],
            "directories": [],
            "additional_exclusions": []
        }

# Entropy thresholds for different types of secrets
ENTROPY_THRESHOLDS = {
    'password': 4.0,      # Lower threshold for passwords
    'api_key': 4.5,       # Higher for API keys
    'token': 4.0,         # Medium for tokens
    'secret': 4.0,        # Medium for generic secrets
    'generic_key': 4.3,   # Optimal threshold for generic "key" patterns (filters programming terms, catches secrets)
    'default': 4.0        # Default threshold
}

# Patterns for detecting secrets with their specific requirements
PATTERNS: List[Tuple[str, str, Dict]] = [
    # AWS - High entropy requirement
    (r'(?i)aws[_\-\.]*(access|secret|key)[_\-\.]*\s*[=:]\s*[A-Za-z0-9/\+=]{16,}', 'AWS Credential', {'min_length': 16, 'require_entropy': True, 'threshold': 4.5}),
    (r'AKIA[0-9A-Z]{16}', 'AWS Access Key ID', {'min_length': 20, 'require_entropy': True, 'threshold': 4.5}),
    
    # Private Keys - No entropy check needed, pattern is sufficient
    (r'(?i)-----BEGIN\s+(?:RSA|OPENSSH|DSA|EC|PGP)\s+PRIVATE\s+KEY-----[A-Za-z0-9/\+=\s]+-----END', 'Private Key', {'require_entropy': False}),
    (r'(?i)ssh-rsa\s+[A-Za-z0-9/\+=]{32,}', 'SSH Key', {'require_entropy': False}),
    
    # API Keys & Tokens - More specific patterns to avoid false positives
    # Only match when "api" and "key" are together, not just "key" alone
    # Capture only the value part (with optional quotes) so entropy is computed correctly on the secret itself
    # Improved pattern to handle both quoted and unquoted values with broader character set
    (r"(?i)(?:api[_\-\.]?key|apikey|api_key)[_\-\.]*\s*[=:]\s*[\"\']?([A-Za-z0-9_\-\.=+/]{12,})[\"\']?", 'API Key', {'min_length': 12, 'require_entropy': True, 'threshold': 4.5, 'value_group': 1}),
    # Additional pattern for unquoted API keys that might be followed by whitespace, semicolon, comma, or end of line
    (r"(?i)(?:api[_\-\.]?key|apikey|api_key)[_\-\.]*\s*[=:]\s*([A-Za-z0-9_\-\.=+/]{12,})(?:\s|$|;|,|\))", 'API Key (Unquoted)', {'min_length': 12, 'require_entropy': True, 'threshold': 4.5, 'value_group': 1}),
    (r'(?i)bearer\s+[A-Za-z0-9_\-\.=]{20,}', 'Bearer Token', {'min_length': 20, 'require_entropy': True, 'threshold': 4.0}),
    (r'ghp_[0-9a-zA-Z]{36}', 'GitHub Personal Access Token', {'require_entropy': False}),  # Pattern is specific enough
    (r'github_pat_[0-9a-zA-Z]{82}', 'GitHub Fine-grained PAT', {'require_entropy': False}),  # Pattern is specific enough
    (r'sk-[a-zA-Z0-9]{48}', 'OpenAI API Key', {'require_entropy': False}),  # Pattern is specific enough
    (r'AIza[0-9A-Za-z\-_]{35}', 'Google API Key', {'require_entropy': False}),  # Pattern is specific enough
    
    # Additional specific API key patterns for better detection
    (r'(?i)(?:api[_\-\.]?key|apikey|api_key)[_\-\.]*\s*[=:]\s*[\"\']?(sk-[a-zA-Z0-9]{48})[\"\']?', 'OpenAI API Key (Assignment)', {'require_entropy': False, 'value_group': 1}),
    (r'(?i)(?:api[_\-\.]?key|apikey|api_key)[_\-\.]*\s*[=:]\s*[\"\']?(ghp_[0-9a-zA-Z]{36})[\"\']?', 'GitHub PAT (Assignment)', {'require_entropy': False, 'value_group': 1}),
    (r'(?i)(?:api[_\-\.]?key|apikey|api_key)[_\-\.]*\s*[=:]\s*[\"\']?(AIza[0-9A-Za-z\-_]{35})[\"\']?', 'Google API Key (Assignment)', {'require_entropy': False, 'value_group': 1}),
    
    # JWT Tokens - No entropy check needed, structure is sufficient
    # Improved pattern to capture full JWT tokens including those with special characters
    (r'eyJ[A-Za-z0-9-_=+/]{10,}\.[A-Za-z0-9-_=+/]{10,}\.[A-Za-z0-9-_=+/]{10,}', 'JWT Token', {'require_entropy': False}),
    
    # Generic Key patterns - Very high entropy requirement to filter out programming terms
    # This catches things like "key = 'some_actual_secret'" but filters out "key = 'buttonkey'"
    (r'(?i)\bkey[_\-\.]*\s*[=:]\s*["\']([^"\']{8,})["\']', 'Generic Key Assignment', {'min_length': 8, 'require_entropy': True, 'threshold': 4.3}),
    (r'(?i)(\w*key)\s*[=:]\s*["\']([^"\']{8,})["\']', 'Generic Key Assignment', {'min_length': 8, 'require_entropy': True, 'threshold': 4.3}),
    
    # Passwords - Lower entropy requirement
    (r'(?i)password[_\-\.]?\s*[=:]\s*[^\s]{8,}', 'Password Assignment', {'min_length': 8, 'require_entropy': True, 'threshold': 4.0}),
    (r'(?i)pass[_\-\.]?\s*[=:]\s*[^\s]{8,}', 'Password Assignment', {'min_length': 8, 'require_entropy': True, 'threshold': 4.0}),
    (r'(?i)pwd[_\-\.]?\s*[=:]\s*[^\s]{8,}', 'Password Assignment', {'min_length': 8, 'require_entropy': True, 'threshold': 4.0}),
    
    # Generic Secrets - More specific patterns to avoid UI/programming terms
    (r'(?i)(?:secret|token|credential)[_\-\.]?\s*[=:]\s*[^\s]{12,}', 'Generic Secret', {'min_length': 12, 'require_entropy': True, 'threshold': 4.5}),
    
    # Database Connection Strings - No entropy check needed, pattern is sufficient
    (r'(?i)(jdbc|mongodb|postgresql|mysql).*:\/\/[^\/\s]+:[^\/\s@]+@[^\/\s]+', 'Database Connection String', {'require_entropy': False}),
    
    # Environment Variables - Check based on name
    (r'(?i)export\s+(\w+)\s*=\s*[^\s]{8,}', 'Environment Variable', {'min_length': 8, 'check_name': True}),
    # API Keys in environment variable format
    (r'(?i)(?:API_KEY|APIKEY)\s*=\s*([A-Za-z0-9_\-\.=+/]{12,})', 'API Key (Environment)', {'min_length': 12, 'require_entropy': True, 'threshold': 4.5, 'value_group': 1}),
    # Specific API keys in environment variable format
    (r'(?i)(?:API_KEY|APIKEY)\s*=\s*(sk-[a-zA-Z0-9]{48})', 'OpenAI API Key (Environment)', {'require_entropy': False, 'value_group': 1}),
    (r'(?i)(?:API_KEY|APIKEY)\s*=\s*(ghp_[0-9a-zA-Z]{36})', 'GitHub PAT (Environment)', {'require_entropy': False, 'value_group': 1}),
    (r'(?i)(?:API_KEY|APIKEY)\s*=\s*(AIza[0-9A-Za-z\-_]{35})', 'Google API Key (Environment)', {'require_entropy': False, 'value_group': 1}),
]

# Load exclusions from configuration if available
def _load_exclusions() -> tuple:
    """
    Load exclusions from YAML file if available, otherwise use defaults.
    Returns tuple of (excluded_extensions, excluded_directories)
    """
    # Load exclusions from YAML - Exclusions are now mandatory, not optional
    exclusions = load_exclusions()
    
    # Extract file extensions (remove the asterisk and dot)
    extensions = set()
    for ext_pattern in exclusions.get('file_extensions', []):
        if ext_pattern.startswith('*.'):
            ext = ext_pattern[2:]
            extensions.add(ext)
        elif ext_pattern.startswith('*'):
            ext = ext_pattern[1:]
            extensions.add(ext)
    
    # Extract directory names (remove the ** and slashes)
    directories = set()
    for dir_pattern in exclusions.get('directories', []):
        if '/**' in dir_pattern:
            dir_name = dir_pattern.split('/**')[0]
            if dir_name.startswith('**/'):
                dir_name = dir_name[3:]
            directories.add(dir_name)
        elif dir_pattern.endswith('/'):
            dir_name = dir_pattern[:-1]
            if dir_name.startswith('**/'):
                dir_name = dir_name[3:]
            directories.add(dir_name)
        else:
            # Try to extract directory name from pattern
            parts = dir_pattern.replace('**/', '').replace('/', '')
            if parts:
                directories.add(parts)
    
    return extensions, directories

# File extensions to exclude from scanning - load from YAML if available
EXCLUDED_EXTENSIONS_DEFAULT = {
    'zip', 'gz', 'tar', 'rar', '7z', 'exe', 'dll', 'so', 'dylib',
    'jar', 'war', 'ear', 'class', 'pyc', 'o', 'a', 'lib', 'obj',
    'bin', 'jpg', 'jpeg', 'png', 'gif', 'bmp', 'ico', 'mp3', 'mp4',
    'avi', 'mov', 'wmv', 'flv', 'pdf', 'doc', 'docx', 'xls', 'xlsx',
    'ppt', 'pptx', 'ttf', 'otf', 'woff', 'woff2', 'eot', 'svg',
    'tif', 'tiff', 'ico', 'webp',
    # Add new data file types
    'xlsx', 'xlsb', 'csv', 'tsv', 'json', 'xml',
    'parquet', 'avro', 'orc',
    # Build artifacts (single extensions only - compound extensions handled separately)
    'lock'                      # Package lock files
}

# Directories to exclude from scanning - load from YAML if available
EXCLUDED_DIRECTORIES_DEFAULT = {
    'distribution', 'node_modules', 'vendor', 'build', 'dist',
    'reports', 'scan_results', '__pycache__', '.git',
    'test', 'tests', 'Test', 'Tests'  # Always exclude test directories
}

# Try to load exclusions, but fall back to defaults if there's an error
try:
    yaml_extensions, yaml_directories = _load_exclusions()
    EXCLUDED_EXTENSIONS = EXCLUDED_EXTENSIONS_DEFAULT.union(yaml_extensions)
    EXCLUDED_DIRECTORIES = EXCLUDED_DIRECTORIES_DEFAULT.union(yaml_directories)
except Exception as e:
    # If there's an error loading the exclusions, use the defaults
    print(f"Error loading exclusions: {e}. Using default exclusions.")
    EXCLUDED_EXTENSIONS = EXCLUDED_EXTENSIONS_DEFAULT
    EXCLUDED_DIRECTORIES = EXCLUDED_DIRECTORIES_DEFAULT

# Disallowed file extensions that might contain sensitive data
DISALLOWED_EXTENSIONS = {
    '.crt', '.cer', '.ca-bundle', '.p7b', '.p7c', '.p7s', '.pem',
    '.jceks', '.key', '.keystore', '.jks', '.p12', '.pfx'
}

# HTML report configuration
HTML_CONFIG = {
    'title': 'Genie - Secret Scan Results',
    'styles': {
        'primary_color': '#07439C',
        'error_color': '#d32f2f',
        'background_color': '#f5f5f5',
        'container_background': 'white',
        'header_background': '#f8f9fa',
    }
}

# Function to check if a file should be excluded based on exclusions
def should_exclude_file(file_path: str) -> bool:
    """
    Check if a file should be excluded from scanning based on its path.
    
    Args:
        file_path: Path to the file to check
        
    Returns:
        True if the file should be excluded, False otherwise
    """
    # First check against all exclusion patterns from the YAML file
    # This ensures glob patterns like **/*test*.* are properly evaluated
    for pattern in get_exclusion_patterns():
        if fnmatch.fnmatch(file_path, pattern):
            return True
    
    # Skip files with excluded extensions
    _, ext = os.path.splitext(file_path)
    if ext and ext.lower().lstrip('.') in EXCLUDED_EXTENSIONS:
        return True
    
    # Special handling for minified and build files with compound extensions
    # These files have extensions like .min.js, .bundle.css, etc.
    file_name = os.path.basename(file_path).lower()
    minified_patterns = [
        '.min.js', '.min.css', '.min.mjs',           # Minified files
        '.bundle.js', '.bundle.css', '.bundle.mjs',  # Bundle files
        '.umd.js', '.iife.js', '.esm.js',           # Module format bundles
        '.production.js', '.dev.js',                # Environment-specific builds
        '.vendor.js', '.vendor.css',                # Vendor bundles
        '.chunk.js', '.chunk.css'                   # Webpack chunks
    ]
    
    for pattern in minified_patterns:
        if file_name.endswith(pattern):
            return True
    
    # Also check for source map files and other build artifacts
    if file_name.endswith(('.map', '.d.ts')):
        return True
    
    # Skip files in excluded directories
    path_parts = file_path.split(os.path.sep)
    for excluded_dir in EXCLUDED_DIRECTORIES:
        if excluded_dir in path_parts:
            return True
    
    # Check if the filename contains "test" or "Test"
    file_name = os.path.basename(file_path)
    if "test" in file_name.lower():
        return True
    
    # Special handling for txt and md files - only include if they have project-related content
    # This is a placeholder - the actual implementation would need to examine the file content
    # For now, we'll be conservative and scan txt/md files in case they contain secrets
    
    return False 