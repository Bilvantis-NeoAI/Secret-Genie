#!/usr/bin/env python3
"""Secret scanning module for detecting potential secrets in code."""

import sys
import os
import re
import json
import logging
import subprocess
import platform
import math
from typing import List, Dict, Union, Set, Tuple, Optional, Any
from datetime import datetime
import html
from config import (
    PATTERNS, HTML_CONFIG,
    EXCLUDED_EXTENSIONS, EXCLUDED_DIRECTORIES, ENTROPY_THRESHOLDS,
    should_exclude_file
)
from utils import (
    setup_logging, get_git_metadata,
    is_git_repo, has_unstaged_changes, get_git_diff,
    mask_secret, run_subprocess
)
import webbrowser
from pathlib import Path

class SecretScanner:
    """Scanner for detecting potential secrets in code."""
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        """Initialize the secret scanner."""
        self.logger = logger or logging.getLogger(__name__)
        self.found_secrets: List[Dict[str, Any]] = []
        # Track file_path:line_number combinations to avoid duplicates
        self._seen_file_lines: Set[Tuple[str, int]] = set()
    
    def calculate_entropy(self, value: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not value:
            return 0.0
        
        # Count character frequencies
        freq = {}
        for c in value:
            freq[c] = freq.get(c, 0) + 1
            
        # Calculate entropy
        length = float(len(value))
        return -sum(f/length * math.log2(f/length) for f in freq.values())
    
    def is_suspicious_env_var(self, name: str) -> bool:
        """Check if an environment variable name suggests it contains a secret."""
        name_lower = name.lower()
        
        # Common JSP/Java non-secret patterns that contain "key" but are not secrets
        jsp_safe_patterns = {
            # Method names and common JSP patterns
            'getparameter', 'getattribute', 'setattribute', 'removeattribute',
            'getproperty', 'setproperty', 'getvalue', 'setvalue',
            'getitem', 'setitem', 'haskey', 'containskey',
            'keyup', 'keydown', 'keypress', 'keycode', 'keyname',
            
            # Database and framework patterns
            'primarykey', 'foreignkey', 'uniquekey', 'compositekey',
            'partitionkey', 'sortkey', 'hashkey', 'indexkey',
            
            # UI and frontend patterns
            'buttonkey', 'hotkey', 'shortcutkey', 'accesskey',
            'presskey', 'clickkey', 'eventkey', 'inputkey',
            
            # Configuration and data patterns
            'configkey', 'datakey', 'cachekey', 'storagekey',
            'sessionkey', 'requestkey', 'paramkey', 'headerkey',
            
            # Framework specific
            'actionkey', 'routekey', 'pathkey', 'templatekey',
            'resourcekey', 'messagekey', 'propertykey', 'settingkey'
        }
        
        # If the name matches any safe pattern, it's not suspicious
        if name_lower in jsp_safe_patterns:
            return False
        
        # Check for method call patterns (ends with common method names)
        method_suffixes = ['parameter', 'attribute', 'property', 'value', 'item']
        if any(name_lower.endswith(suffix) for suffix in method_suffixes):
            return False
        
        # Check for common JSP variable naming patterns
        jsp_prefixes = ['get', 'set', 'has', 'is', 'contains', 'remove', 'add']
        if any(name_lower.startswith(prefix) for prefix in jsp_prefixes):
            return False
        
        # Skip authentication status terms that contain "auth" but aren't secrets
        auth_status_terms = {
            'unauthorized', 'unauthorised', 'authenticated', 'unauthenticated',
            'authorized', 'authorised', 'authentication', 'authorization',
            'authstatus', 'authstate', 'authresult', 'autherror', 'authmessage',
            'authresponse', 'authrequest', 'authfailed', 'authsuccess'
        }
        
        if name_lower in auth_status_terms:
            return False
        
        # Original suspicious terms check
        suspicious_terms = {
            'token', 'secret', 'password', 'pwd', 'pass',
            'credential', 'private', 'cert', 'ssh'
        }
        
        # Only check for suspicious terms that are not part of safe patterns
        # and add "key" only if it's not in a safe context
        if 'key' in name_lower:
            # Only consider "key" suspicious if it's:
            # 1. The entire word "key"
            # 2. Or part of clearly suspicious patterns like "apikey", "secretkey"
            if (name_lower == 'key' or 
                any(term in name_lower for term in ['api', 'secret', 'private', 'auth', 'token'])):
                return True
            else:
                return False
        
        # Handle "auth" terms specifically - only flag as suspicious if combined with secret indicators
        if 'auth' in name_lower:
            # Only consider "auth" suspicious if combined with secret-indicating terms
            auth_secret_indicators = ['key', 'token', 'secret', 'credential', 'pass']
            if any(indicator in name_lower for indicator in auth_secret_indicators):
                return True
            else:
                return False  # Status terms like "unauthorized" are not suspicious
        
        return any(term in name_lower for term in suspicious_terms)
    
    def is_file_specific_false_positive(self, value: str, file_path: str) -> bool:
        """Check if a value is a false positive based on file type context."""
        file_ext = file_path.lower().split('.')[-1] if '.' in file_path else ''
        value_lower = value.lower()
        
        # JavaScript/JSP specific false positives
        if file_ext in ('js', 'jsx', 'ts', 'tsx', 'jsp', 'jspx', 'java'):
            # Common JavaScript/JSP patterns that are not secrets
            js_patterns = {
                # Event handling
                'onclick', 'onload', 'onchange', 'onsubmit', 'onfocus', 'onblur',
                'onkeydown', 'onkeyup', 'onkeypress', 'onmousedown', 'onmouseup',
                
                # DOM/UI related
                'classname', 'classlist', 'innerhtml', 'innertext', 'textcontent',
                'getattribute', 'setattribute', 'removeattribute', 'hasattribute',
                'getelementbyid', 'getelementsbyclass', 'queryselector',
                
                # Framework specific (React, Angular, etc.)
                'usestate', 'useeffect', 'usecontext', 'usememo', 'usecallback',
                'componentdidmount', 'componentwillunmount', 'shouldcomponentupdate',
                
                # Common JSP/Servlet terms
                'requestmapping', 'pathvariable', 'requestparam', 'modelandview',
                'httpservletrequest', 'httpservletresponse', 'httpmethod',
                
                # JSP Method calls and parameters
                'getparameter', 'getattribute', 'setattribute', 'removeattribute',
                'getproperty', 'setproperty', 'getvalue', 'setvalue',
                'getitem', 'setitem', 'haskey', 'containskey',
                'getintparameter', 'getstringparameter', 'getbooleanparameter',
                
                # Common JSP parameter names that contain "key"
                'userkey', 'sessionkey', 'requestkey', 'paramkey', 'configkey',
                'messagekey', 'resourcekey', 'propertykey', 'datakey', 'itemkey',
                'pagekey', 'formkey', 'fieldkey', 'inputkey', 'outputkey',
                'sortkey', 'filterkey', 'searchkey', 'querykey', 'resultkey',
                
                # Database and persistence patterns
                'primarykey', 'foreignkey', 'uniquekey', 'compositekey',
                'partitionkey', 'indexkey', 'hashkey', 'entitykey',
                
                # UI and interaction patterns
                'buttonkey', 'hotkey', 'shortcutkey', 'accesskey', 'tabkey',
                'presskey', 'clickkey', 'eventkey', 'keycode', 'keyname',
                'keyup', 'keydown', 'keypress', 'keyboard',
                
                # Configuration and constants
                'contextpath', 'servletpath', 'requesturi', 'querystring',
                'sessionattribute', 'modelattribute', 'restcontroller'
            }
            
            if value_lower in js_patterns:
                return True
                
            # Check for common JavaScript/JSP variable patterns and method calls
            if any(pattern in value_lower for pattern in [
                'document.', 'window.', 'console.', 'jquery.', '$.', 'angular.',
                'react.', 'vue.', 'this.', 'event.', 'target.', 'currenttarget.',
                'response.', 'request.', 'session.', 'application.', 'pagecontext.',
                # JSP/Java method call patterns
                '.getparameter(', '.getattribute(', '.setattribute(', '.getproperty(',
                '.setproperty(', '.getvalue(', '.setvalue(', '.get(', '.put(',
                '.containskey(', '.haskey(', '.keyup(', '.keydown(', '.keypress('
            ]):
                return True
        
        # CSS specific false positives
        elif file_ext in ('css', 'scss', 'sass', 'less'):
            css_patterns = {
                'background', 'foreground', 'border', 'margin', 'padding',
                'position', 'display', 'visibility', 'overflow', 'float',
                'fontfamily', 'fontsize', 'fontweight', 'textalign', 'textdecoration',
                'lineheight', 'letterspacing', 'wordspacing', 'whitespace'
            }
            
            if value_lower in css_patterns:
                return True
        
        # XML/HTML specific false positives
        elif file_ext in ('xml', 'html', 'htm', 'xhtml'):
            html_patterns = {
                'charset', 'viewport', 'description', 'keywords', 'author',
                'generator', 'robots', 'canonical', 'stylesheet', 'javascript',
                'alternate', 'shortcut', 'manifest', 'application'
            }
            
            if value_lower in html_patterns:
                return True
        
        # Terraform specific false positives
        elif file_ext == 'tf':
            # Check if the value contains Terraform-specific keywords that are not secrets
            terraform_keywords = ['keyrings', 'networks', 'subnetworks', 'projects/']
            if any(keyword in value_lower for keyword in terraform_keywords):
                return True
            
            # Additional Terraform-specific patterns that are not secrets
            terraform_patterns = {
                # Common Terraform resource types
                'google_compute_network', 'google_compute_subnetwork', 'google_kms_keyring',
                'google_project', 'google_project_service', 'google_project_iam',
                
                # Terraform data sources
                'data.google_project', 'data.google_compute_network', 'data.google_kms_keyring',
                
                # Common Terraform variable patterns
                'var.project_id', 'var.network_name', 'var.subnetwork_name', 'var.keyring_name',
                'local.project_id', 'local.network_name', 'local.subnetwork_name',
                
                # Terraform function calls
                'terraform.workspace', 'terraform.workspace_name', 'terraform.workspace_id'
            }
            
            if value_lower in terraform_patterns:
                return True
        
        # YAML specific false positives
        elif file_ext in ('yaml', 'yml'):
            # Common YAML patterns that are not secrets
            yaml_patterns = {
                # Kubernetes and common YAML resource types
                'apiVersion', 'kind', 'metadata', 'spec', 'data', 'config',
                'environment', 'env', 'namespace', 'labels', 'annotations',
                'selector', 'matchLabels', 'template', 'containers', 'ports',
                'volumes', 'configMap', 'secret', 'service', 'deployment',
                'pod', 'node', 'cluster', 'context', 'current-context',
                
                # Common YAML values
                'v1', 'v1beta1', 'apps/v1', 'batch/v1', 'networking.k8s.io/v1',
                'ClusterIP', 'NodePort', 'LoadBalancer', 'ClusterIP',
                'Always', 'IfNotPresent', 'Never', 'OnFailure', 'OnSuccess',
                'ReadWriteOnce', 'ReadOnlyMany', 'ReadWriteMany',
                
                # YAML configuration values
                'true', 'false', 'null', '~', 'yes', 'no', 'on', 'off',
                'default', 'custom', 'standard', 'basic', 'advanced'
            }
            
            if value_lower in yaml_patterns:
                return True
            
            # Check for YAML-specific patterns that are not secrets
            if any(pattern in value_lower for pattern in [
                'apiVersion:', 'kind:', 'metadata:', 'spec:', 'data:', 'config:',
                'environment:', 'env:', 'namespace:', 'labels:', 'annotations:',
                'selector:', 'matchLabels:', 'template:', 'containers:', 'ports:',
                'volumes:', 'configMap:', 'secret:', 'service:', 'deployment:',
                'pod:', 'node:', 'cluster:', 'context:', 'current-context:'
            ]):
                return True
        
        # Shell script specific false positives
        elif file_ext in ('sh', 'bash', 'zsh', 'fish', 'ksh'):
            # Common shell patterns that are not secrets
            shell_patterns = {
                # Shell builtins and commands
                '#!/bin/', '#!/usr/bin/', 'set -', 'export', 'unset',
                'source', 'alias', 'function', 'if', 'then', 'else',
                'elif', 'fi', 'case', 'esac', 'for', 'do', 'done',
                'while', 'until', 'select', 'break', 'continue',
                'return', 'exit', 'echo', 'printf', 'read', 'test',
                'eval', 'exec', 'shift', 'getopts', 'trap',
                
                # Common shell variables
                'PATH', 'HOME', 'USER', 'SHELL', 'TERM', 'PWD',
                'LANG', 'LC_ALL', 'TZ', 'HOSTNAME', 'HOSTTYPE',
                'OSTYPE', 'MACHTYPE', 'EDITOR', 'VISUAL', 'PAGER',
                'MANPATH', 'INFOPATH', 'LD_LIBRARY_PATH', 'PKG_CONFIG_PATH',
                'PYTHONPATH', 'JAVA_HOME', 'ANDROID_HOME', 'NODE_PATH',
                'GOPATH', 'CARGO_HOME', 'RUSTUP_HOME', 'NVM_DIR',
                'RVM_PATH', 'RBENV_ROOT', 'PYENV_ROOT', 'NODENV_ROOT',
                
                # Shell file operations
                'cd', 'pwd', 'ls', 'cp', 'mv', 'rm', 'mkdir', 'rmdir',
                'ln', 'chmod', 'chown', 'chgrp', 'touch', 'cat', 'head',
                'tail', 'grep', 'sed', 'awk', 'sort', 'uniq', 'wc',
                'cut', 'paste', 'join', 'split', 'tr', 'expand', 'unexpand'
            }
            
            if value_lower in shell_patterns:
                return True
            
            # Check for shell-specific patterns that are not secrets
            if any(pattern in value_lower for pattern in [
                '#!/bin/', '#!/usr/bin/', 'set -', 'export ', 'unset ',
                'source ', '. ', 'alias ', 'function ', 'if ', 'then ',
                'else ', 'elif ', 'fi', 'case ', 'esac', 'for ', 'do ',
                'done', 'while ', 'until ', 'select ', 'break', 'continue',
                'return', 'exit', 'echo ', 'printf ', 'read ', 'test ',
                'eval ', 'exec ', 'shift', 'getopts', 'trap ',
                'umask', 'ulimit', 'cd ', 'pwd', 'ls ', 'cp ', 'mv ',
                'rm ', 'mkdir', 'rmdir', 'ln ', 'chmod', 'chown', 'chgrp'
            ]):
                return True
        
        return False
    
    def should_skip_value(self, value: str, file_path: str = '') -> bool:
        """Check if a value should be skipped (common non-secrets)."""
        # Skip very short values
        if len(value) < 6:
            return True
        
        # Skip very long values (likely to be encoded data, minified code, or large objects)
        # Real secrets are typically 6-500 characters
        if len(value) > 500:
            return True
        
        # Check file-specific false positives first
        if file_path and self.is_file_specific_false_positive(value, file_path):
            return True
            
        # Skip common non-secret values
        common_values = {
            'true', 'false', 'none', 'null', 'undefined', 'localhost',
            'password', 'username', 'user', 'test', 'example', 'demo'
        }
        
        # Common programming terms that are often false positives
        programming_terms = {
            # UI/UX related terms
            'button', 'click', 'press', 'hover', 'focus', 'blur', 'select',
            'submit', 'cancel', 'close', 'open', 'toggle', 'show', 'hide',
            'display', 'visible', 'hidden', 'active', 'disabled', 'enabled',
            
            # Key-related terms that are not secrets
            'primarykey', 'foreignkey', 'buttonkey', 'presskey', 'hotkey',
            'shortcutkey', 'accesskey', 'tabkey', 'escapekey', 'enterkey',
            'spacekey', 'arrowkey', 'functionkey', 'controlkey', 'shiftkey',
            'altkey', 'metakey', 'keycode', 'keyname', 'keyvalue', 'keytype',
            'keymap', 'keybind', 'keypress', 'keydown', 'keyup', 'keyboard',
            
            # Common variable values
            'string', 'number', 'boolean', 'object', 'array', 'function',
            'method', 'property', 'attribute', 'element', 'component',
            'module', 'package', 'library', 'framework', 'plugin',
            
            # File paths and extensions
            'public', 'private', 'static', 'assets', 'images', 'scripts',
            'styles', 'components', 'templates', 'views', 'models',
            'controllers', 'services', 'utils', 'helpers', 'config',
            
            # Database/SQL terms
            'database', 'table', 'column', 'index', 'constraint', 'trigger',
            'procedure', 'varchar', 'integer', 'datetime', 'timestamp',
            
            # Web development terms
            'request', 'response', 'session', 'cookie', 'header', 'body',
            'param', 'query', 'route', 'endpoint', 'middleware', 'controller',
            'service', 'repository', 'entity', 'model', 'view', 'template',
            
            # Generic application terms
            'application', 'version', 'production', 'development', 'staging',
            'environment', 'profile', 'configuration', 'settings', 'options',
            'preferences', 'defaults', 'constants', 'variables', 'parameters',
            
            # YAML-specific terms
            'apiVersion', 'kind', 'metadata', 'spec', 'data', 'config',
            'environment', 'env', 'namespace', 'labels', 'annotations',
            'selector', 'matchLabels', 'template', 'containers', 'ports',
            'volumes', 'configMap', 'secret', 'service', 'deployment',
            'pod', 'node', 'cluster', 'context', 'current-context',
            'v1', 'v1beta1', 'apps/v1', 'batch/v1', 'networking.k8s.io/v1',
            'ClusterIP', 'NodePort', 'LoadBalancer', 'Always', 'IfNotPresent',
            'Never', 'OnFailure', 'OnSuccess', 'ReadWriteOnce', 'ReadOnlyMany',
            'ReadWriteMany', 'true', 'false', 'null', '~', 'yes', 'no', 'on', 'off',
            
            # Shell-specific terms
            '#!/bin/', '#!/usr/bin/', 'set -', 'export', 'unset', 'source',
            'alias', 'function', 'if', 'then', 'else', 'elif', 'fi', 'case',
            'esac', 'for', 'do', 'done', 'while', 'until', 'select',
            'break', 'continue', 'return', 'exit', 'echo', 'printf', 'read',
            'test', 'eval', 'exec', 'shift', 'getopts', 'trap', 'umask',
            'ulimit', 'cd', 'pwd', 'ls', 'cp', 'mv', 'rm', 'mkdir', 'rmdir',
            'ln', 'chmod', 'chown', 'chgrp', 'touch', 'cat', 'head', 'tail',
            'grep', 'sed', 'awk', 'sort', 'uniq', 'wc', 'cut', 'paste',
            'join', 'split', 'tr', 'expand', 'unexpand', 'nl', 'fold', 'fmt',
            'pr', 'column', 'col', 'tac', 'rev', 'shuf', 'base64', 'hexdump',
            'od', 'xxd', 'sum', 'cksum', 'md5sum', 'sha1sum', 'sha256sum',
            'sha512sum', 'b2sum', 'sha224sum', 'sha384sum', 'sha512t256sum'
        }
        
        # Common natural language terms that have high entropy but aren't secrets
        natural_language_terms = {
            # Month names
            'january', 'february', 'march', 'april', 'may', 'june',
            'july', 'august', 'september', 'october', 'november', 'december',
            'jan', 'feb', 'mar', 'apr', 'jun', 'jul', 'aug', 'sep', 'oct', 'nov', 'dec',
            
            # Day names
            'monday', 'tuesday', 'wednesday', 'thursday', 'friday', 'saturday', 'sunday',
            'mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun',
            
            # Common descriptive words that can have high entropy
            'description', 'information', 'documentation', 'explanation', 'content',
            'message', 'comment', 'title', 'heading', 'label', 'caption', 'text',
            'example', 'sample', 'placeholder', 'default', 'standard', 'normal',
            'regular', 'typical', 'common', 'general', 'basic', 'simple',
            
            # Time-related terms
            'morning', 'afternoon', 'evening', 'night', 'today', 'tomorrow',
            'yesterday', 'weekend', 'weekday', 'minute', 'hour', 'second',
            
            # Status and state terms
            'success', 'failure', 'error', 'warning', 'notice', 'info',
            'complete', 'incomplete', 'pending', 'processing', 'finished',
            'started', 'stopped', 'running', 'idle', 'waiting',
            
            # Authentication and authorization status terms (not secrets)
            'unauthorized', 'unauthorised', 'forbidden', 'denied', 'rejected',
            'authenticated', 'unauthenticated', 'authorized', 'authorised',
            'permission', 'permissions', 'privileges', 'access', 'accessible',
            'inaccessible', 'restricted', 'unrestricted', 'public', 'protected',
            'allowed', 'disallowed', 'granted', 'revoked', 'expired', 'valid',
            'invalid', 'verified', 'unverified', 'confirmed', 'unconfirmed',
            
            # HTTP status and error terms
            'notfound', 'badrequest', 'servererror', 'timeout', 'conflict',
            'redirect', 'moved', 'created', 'accepted', 'nocontent',
            'modified', 'cached', 'gateway', 'unavailable',
            
        # Common file and path terms
        'filename', 'filepath', 'directory', 'folder', 'document', 'file',
        'extension', 'format', 'type', 'size', 'length', 'width', 'height',
        
        # Common shell environment variables
        'PATH', 'HOME', 'USER', 'SHELL', 'TERM', 'PWD', 'LANG', 'LC_ALL',
        'TZ', 'HOSTNAME', 'HOSTTYPE', 'OSTYPE', 'MACHTYPE', 'EDITOR',
        'VISUAL', 'PAGER', 'MANPATH', 'INFOPATH', 'LD_LIBRARY_PATH',
        'PKG_CONFIG_PATH', 'PYTHONPATH', 'JAVA_HOME', 'ANDROID_HOME',
        'NODE_PATH', 'GOPATH', 'CARGO_HOME', 'RUSTUP_HOME', 'NVM_DIR',
        'RVM_PATH', 'RBENV_ROOT', 'PYENV_ROOT', 'NODENV_ROOT',
        
        # Common YAML values
        'apiVersion', 'kind', 'metadata', 'spec', 'data', 'config',
        'environment', 'env', 'namespace', 'labels', 'annotations',
        'selector', 'matchLabels', 'template', 'containers', 'ports',
        'volumes', 'configMap', 'secret', 'service', 'deployment',
        'pod', 'node', 'cluster', 'context', 'current-context',
        
        # Common URL and hostname terms
        'localhost', '127.0.0.1', '0.0.0.0', '::1', 'api', 'www',
        'mail', 'smtp', 'pop', 'imap', 'ftp', 'ssh', 'dns', 'ns1',
        'ns2', 'mx', 'web', 'app', 'db', 'redis', 'elasticsearch',
        'kafka', 'rabbitmq', 'postgres', 'mysql', 'mongodb', 'cassandra',
        'influxdb', 'prometheus', 'grafana', 'dev', 'test', 'staging',
        'prod', 'uat', 'qa', 'preview', 'demo', 'sandbox'
        }
        
        # Check against all common values (case-insensitive)
        value_lower = value.lower()
        if value_lower in common_values or value_lower in programming_terms or value_lower in natural_language_terms:
            return True
            
        # Check if the value is a URL or hostname (common false positives)
        if self.is_url_or_hostname(value):
            return True
            
        # Skip values that are clearly not secrets based on patterns
        # File paths, common formats
        if any(pattern in value_lower for pattern in [
            '.js', '.css', '.html', '.jsp', '.php',      # File extensions
            '.png', '.jpg', '.gif', '.svg',              # Image extensions
            '${', '#{', '{{',                            # Template syntax
            'function(', 'return ', 'var ', 'let ', 'const ',  # Code keywords
            # YAML-specific patterns
            'apiVersion:', 'kind:', 'metadata:', 'spec:', 'data:', 'config:',
            'environment:', 'env:', 'namespace:', 'labels:', 'annotations:',
            'selector:', 'matchLabels:', 'template:', 'containers:', 'ports:',
            'volumes:', 'configMap:', 'secret:', 'service:', 'deployment:',
            'pod:', 'node:', 'cluster:', 'context:', 'current-context:',
            # Shell-specific patterns
            '#!/bin/', '#!/usr/bin/', 'set -', 'export ', 'unset ',
            'source ', '. ', 'alias ', 'function ', 'if ', 'then ',
            'else ', 'elif ', 'fi', 'case ', 'esac', 'for ', 'do ',
            'done', 'while ', 'until ', 'select ', 'break', 'continue',
            'return', 'exit', 'echo ', 'printf ', 'read ', 'test ',
            'eval ', 'exec ', 'shift', 'getopts', 'trap '
        ]):
            return True
        
        # Skip natural language patterns that aren't secrets
        # Sentences with spaces and common words
        if ' ' in value_lower:
            common_sentence_words = {'the', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by'}
            words = value_lower.split()
            if len(words) >= 2 and any(word in common_sentence_words for word in words):
                return True
        
        # Skip date and time patterns
        date_time_patterns = [
            r'\d{4}-\d{2}-\d{2}',           # YYYY-MM-DD
            r'\d{2}\/\d{2}\/\d{4}',         # MM/DD/YYYY
            r'\d{2}-\d{2}-\d{4}',           # MM-DD-YYYY
            r'\d{2}:\d{2}:\d{2}',           # HH:MM:SS
            r'\d{2}:\d{2}',                 # HH:MM
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', # ISO datetime
        ]
        
        for pattern in date_time_patterns:
            if re.search(pattern, value):
                return True
        
        # Skip descriptive phrases (contain common descriptive words)
        descriptive_indicators = [
            'description', 'message', 'text', 'content', 'title', 'label',
            'comment', 'note', 'info', 'details', 'summary', 'caption',
            # Authentication/authorization status messages
            'unauthorized', 'unauthorised', 'forbidden', 'denied', 'access',
            'permission', 'authenticated', 'authorized', 'authorised',
            'status', 'error', 'warning', 'notice', 'alert', 'notification',
            # HTTP and API response terms
            'response', 'request', 'header', 'body', 'payload', 'endpoint'
        ]
        
        if any(indicator in value_lower for indicator in descriptive_indicators):
            return True
        
        # Skip common authentication/authorization phrases and error messages
        auth_message_patterns = [
            'access denied', 'permission denied', 'unauthorized access',
            'authentication failed', 'authorization failed', 'login failed',
            'invalid credentials', 'session expired', 'token expired',
            'forbidden access', 'access forbidden', 'not authorized',
            'authentication required', 'login required', 'credentials required'
        ]
        
        for pattern in auth_message_patterns:
            if pattern in value_lower:
                return True
            
        # Skip values that look like configuration keys or identifiers
        if value_lower.endswith(('key', 'id', 'name', 'type', 'mode', 'flag', 'option')):
            # Check if it's likely a configuration key rather than a secret
            if any(prefix in value_lower for prefix in [
                'button', 'press', 'click', 'hover', 'focus', 'tab', 'escape',
                'enter', 'space', 'arrow', 'function', 'control', 'shift',
                'alt', 'meta', 'primary', 'foreign', 'unique', 'composite'
            ]):
                return True
        
        # Skip YAML-specific configuration values
        if file_path and file_path.lower().endswith(('.yaml', '.yml')):
            yaml_config_values = {
                'v1', 'v1beta1', 'apps/v1', 'batch/v1', 'networking.k8s.io/v1',
                'ClusterIP', 'NodePort', 'LoadBalancer', 'Always', 'IfNotPresent',
                'Never', 'OnFailure', 'OnSuccess', 'ReadWriteOnce', 'ReadOnlyMany',
                'ReadWriteMany', 'true', 'false', 'null', '~', 'yes', 'no', 'on', 'off',
                'default', 'custom', 'standard', 'basic', 'advanced', 'development',
                'staging', 'production', 'test', 'debug', 'release', 'stable'
            }
            if value_lower in yaml_config_values:
                return True
        
        # Skip shell-specific configuration values
        if file_path and file_path.lower().endswith(('.sh', '.bash', '.zsh', '.fish', '.ksh')):
            shell_config_values = {
                '#!/bin/bash', '#!/bin/sh', '#!/usr/bin/bash', '#!/usr/bin/sh',
                'set -e', 'set -u', 'set -o', 'set +e', 'set +u', 'set +o',
                'export PATH', 'export HOME', 'export USER', 'export SHELL',
                'export TERM', 'export PWD', 'export LANG', 'export LC_ALL',
                'export TZ', 'export HOSTNAME', 'export HOSTTYPE', 'export OSTYPE',
                'export MACHTYPE', 'export EDITOR', 'export VISUAL', 'export PAGER'
            }
            if value_lower in shell_config_values:
                return True
                
        return False
    
    def should_skip_terraform_line(self, line: str, file_path: str) -> bool:
        """Check if a line should be skipped for Terraform files based on specific keywords."""
        if not file_path.lower().endswith('.tf'):
            return False
        
        line_lower = line.lower()
        
        # Skip lines containing Terraform-specific keywords that are not secrets
        terraform_keywords = ['keyrings', 'networks', 'subnetworks', 'projects/']
        if any(keyword in line_lower for keyword in terraform_keywords):
            return True
        
        # Skip lines with common Terraform resource definitions that are not secrets
        terraform_resource_patterns = [
            'google_compute_network', 'google_compute_subnetwork', 'google_kms_keyring',
            'google_project', 'google_project_service', 'google_project_iam',
            'data.google_project', 'data.google_compute_network', 'data.google_kms_keyring'
        ]
        
        if any(pattern in line_lower for pattern in terraform_resource_patterns):
            return True
        
        return False
    
    def should_skip_yaml_line(self, line: str, file_path: str) -> bool:
        """Check if a line should be skipped for YAML files based on specific keywords."""
        if not file_path.lower().endswith(('.yaml', '.yml')):
            return False
        
        line_lower = line.lower()
        
        # Skip lines containing YAML-specific keywords that are not secrets
        # But be more specific to avoid skipping legitimate secret assignments
        yaml_keywords = [
            'api_version', 'kind', 'metadata', 'spec', 'namespace', 'labels', 'annotations',
            'selector', 'match_labels', 'template', 'containers', 'ports',
            'volumes', 'configmaps', 'secrets', 'services', 'deployments',
            'pods', 'nodes', 'clusters', 'contexts', 'current-context'
        ]
        
        # Check if the line contains these keywords in a way that suggests it's not a secret
        # Skip only if the keyword appears as a key (followed by colon) or in specific contexts
        for keyword in yaml_keywords:
            if keyword in line_lower:
                # Skip if it's a YAML key (followed by colon)
                if f'{keyword}:' in line_lower:
                    return True
                # Skip if it's a Kubernetes resource type
                if keyword in ['kind', 'api_version', 'metadata', 'spec']:
                    return True
                # Skip if it's a template or container definition
                if keyword in ['template', 'containers', 'ports', 'volumes']:
                    return True
                # Skip if it's a selector or label definition
                if keyword in ['selector', 'labels', 'annotations']:
                    return True
                # Skip if it's a service or deployment definition
                if keyword in ['services', 'deployments', 'pods', 'nodes', 'clusters']:
                    return True
        
        # Skip lines with common YAML resource definitions that are not secrets
        yaml_resource_patterns = [
            'apiVersion:', 'kind:', 'metadata:', 'spec:', 'data:', 'config:',
            'environment:', 'env:', 'namespace:', 'labels:', 'annotations:',
            'selector:', 'matchLabels:', 'template:', 'containers:', 'ports:',
            'volumes:', 'configMap:', 'secret:', 'service:', 'deployment:',
            'pod:', 'node:', 'cluster:', 'context:', 'current-context:'
        ]
        
        if any(pattern in line_lower for pattern in yaml_resource_patterns):
            return True
        
        # Skip lines with common YAML resource definitions that are not secrets
        yaml_resource_patterns = [
            'apiVersion:', 'kind:', 'metadata:', 'spec:', 'data:', 'config:',
            'environment:', 'env:', 'namespace:', 'labels:', 'annotations:',
            'selector:', 'matchLabels:', 'template:', 'containers:', 'ports:',
            'volumes:', 'configMap:', 'secret:', 'service:', 'deployment:',
            'pod:', 'node:', 'cluster:', 'context:', 'current-context:'
        ]
        
        if any(pattern in line_lower for pattern in yaml_resource_patterns):
            return True
        
        # Skip lines with YAML comment indicators
        if line.strip().startswith('#'):
            return True
        
        return False
    
    def should_skip_shell_line(self, line: str, file_path: str) -> bool:
        """Check if a line should be skipped for shell script files based on specific keywords."""
        if not file_path.lower().endswith(('.sh', '.bash', '.zsh', '.fish', '.ksh')):
            return False
        
        line_lower = line.lstrip().lower()
        
        # Skip lines containing shell-specific keywords that are not secrets
        shell_keywords = [
            '#!/bin/', '#!/usr/bin/', 'set -', 'export ', 'unset ',
            'source ', '. ', 'alias ', 'function ', 'if ', 'then ',
            'else ', 'elif ', 'fi', 'case ', 'esac', 'for ', 'do ',
            'done', 'while ', 'until ', 'select ', 'break', 'continue',
            'return', 'exit', 'echo ', 'printf ', 'read ', 'test ',
            'eval ', 'exec ', 'exec', 'shift', 'getopts', 'trap ',
            'umask', 'ulimit', 'cd ', 'pwd', 'ls ', 'cp ', 'mv ',
            'rm ', 'mkdir', 'rmdir', 'ln ', 'chmod', 'chown', 'chgrp',
            'touch', 'cat ', 'head', 'tail', 'grep ', 'sed ', 'awk ',
            'sort', 'uniq', 'wc ', 'cut ', 'paste', 'join', 'split',
            'tr ', 'expand', 'unexpand', 'nl', 'fold', 'fmt', 'pr ',
            'column', 'col', 'tac', 'rev', 'shuf', 'base64', 'hexdump',
            'od', 'xxd', 'sum', 'cksum', 'md5sum', 'sha1sum', 'sha256sum',
            'sha512sum', 'b2sum', 'sha224sum', 'sha384sum', 'sha512t256sum'
        ]
        
        if any(keyword in line_lower for keyword in shell_keywords):
            return True
        
        # Skip lines with shell comment indicators
        if line.strip().startswith('#'):
            return True
        
        # Skip lines with common shell variable assignments that are not secrets
        shell_var_patterns = [
            'PATH=', 'HOME=', 'USER=', 'SHELL=', 'TERM=', 'PWD=',
            'LANG=', 'LC_ALL=', 'TZ=', 'HOSTNAME=', 'HOSTTYPE=',
            'OSTYPE=', 'MACHTYPE=', 'EDITOR=', 'VISUAL=', 'PAGER=',
            'MANPATH=', 'INFOPATH=', 'LD_LIBRARY_PATH=', 'PKG_CONFIG_PATH=',
            'PYTHONPATH=', 'JAVA_HOME=', 'ANDROID_HOME=', 'NODE_PATH=',
            'GOPATH=', 'CARGO_HOME=', 'RUSTUP_HOME=', 'NVM_DIR=',
            'RVM_PATH=', 'RBENV_ROOT=', 'PYENV_ROOT=', 'NODENV_ROOT='
        ]
        
        if any(pattern in line_lower for pattern in shell_var_patterns):
            return True
        
        # Skip lines with shell function definitions
        if re.match(r'^\s*\w+\s*\(\s*\)\s*\{?\s*$', line):
            return True
        
        # Skip lines with shell conditional statements
        if re.match(r'^\s*(if|elif|while|until|for)\s+', line):
            return True
        
        return False
    
    def is_url_or_hostname(self, value: str) -> bool:
        """Check if a value is a URL or hostname that should be skipped."""
        value_lower = value.lower()
        
        # Common URL schemes
        url_schemes = ['http://', 'https://', 'ftp://', 'file://', 'sftp://', 'ssh://', 'ws://', 'wss://']
        if any(value_lower.startswith(scheme) for scheme in url_schemes):
            return True
        
        # Common domain extensions
        domain_extensions = [
            '.com', '.org', '.net', '.edu', '.gov', '.mil', '.int',
            '.co', '.io', '.ai', '.app', '.dev', '.tech', '.cloud',
            '.info', '.biz', '.name', '.pro', '.aero', '.coop',
            '.museum', '.travel', '.jobs', '.mobi', '.tel', '.xxx',
            '.ac', '.ad', '.ae', '.af', '.ag', '.al', '.am', '.an',
            '.ao', '.aq', '.ar', '.as', '.at', '.au', '.aw', '.az',
            '.ba', '.bb', '.bd', '.be', '.bf', '.bg', '.bh', '.bi',
            '.bj', '.bm', '.bn', '.bo', '.br', '.bs', '.bt', '.bw',
            '.by', '.bz', '.ca', '.cc', '.cd', '.cf', '.cg', '.ch',
            '.ci', '.ck', '.cl', '.cm', '.cn', '.cr', '.cu', '.cv',
            '.cw', '.cx', '.cy', '.cz', '.de', '.dj', '.dk', '.dm',
            '.do', '.dz', '.ec', '.ee', '.eg', '.er', '.es', '.et',
            '.eu', '.fi', '.fj', '.fk', '.fm', '.fo', '.fr', '.ga',
            '.gd', '.ge', '.gf', '.gg', '.gh', '.gi', '.gl', '.gm',
            '.gn', '.gp', '.gq', '.gr', '.gs', '.gt', '.gu', '.gw',
            '.gy', '.hk', '.hm', '.hn', '.hr', '.ht', '.hu', '.id',
            '.il', '.im', '.in', '.iq', '.ir', '.is', '.it', '.je',
            '.jm', '.jo', '.jp', '.ke', '.kg', '.kh', '.ki', '.km',
            '.kn', '.kp', '.kr', '.kw', '.ky', '.kz', '.la', '.lb',
            '.lc', '.li', '.lk', '.lr', '.ls', '.lt', '.lu', '.lv',
            '.ly', '.ma', '.mc', '.md', '.me', '.mg', '.mh', '.mk',
            '.ml', '.mm', '.mn', '.mo', '.mp', '.mq', '.mr', '.ms',
            '.mt', '.mu', '.mv', '.mw', '.mx', '.my', '.mz', '.na',
            '.nc', '.ne', '.nf', '.ng', '.ni', '.nl', '.no', '.np',
            '.nr', '.nu', '.nz', '.om', '.pa', '.pe', '.pf', '.pg',
            '.ph', '.pk', '.pl', '.pm', '.pn', '.pr', '.ps', '.pt',
            '.pw', '.py', '.qa', '.re', '.ro', '.rs', '.ru', '.rw',
            '.sa', '.sb', '.sc', '.sd', '.se', '.sg', '.sh', '.si',
            '.sk', '.sl', '.sm', '.sn', '.so', '.sr', '.st', '.su',
            '.sv', '.sy', '.sz', '.tc', '.td', '.tf', '.tg', '.th',
            '.tj', '.tk', '.tl', '.tm', '.tn', '.to', '.tr', '.tt',
            '.tv', '.tw', '.tz', '.ua', '.ug', '.uk', '.us', '.uy',
            '.uz', '.va', '.vc', '.ve', '.vg', '.vi', '.vn', '.vu',
            '.wf', '.ws', '.ye', '.yt', '.za', '.zm', '.zw'
        ]
        
        # Check if value contains domain extensions
        # But exclude known secret patterns that might contain domain-like strings
        if any(ext in value_lower for ext in domain_extensions):
            # Skip if this looks like a known secret pattern
            if self.is_likely_secret_pattern(value):
                return False
            return True
        
        # Common hostname patterns
        hostname_patterns = [
            # Local development
            'localhost', '127.0.0.1', '0.0.0.0', '::1',
            'dev.local', 'test.local', 'staging.local', 'prod.local',
            'local.dev', 'local.test', 'local.staging', 'local.prod',
            
            # Common service names
            'api', 'www', 'mail', 'smtp', 'pop', 'imap', 'ftp', 'ssh',
            'dns', 'ns1', 'ns2', 'mx', 'web', 'app', 'db', 'redis',
            'elasticsearch', 'kafka', 'rabbitmq', 'postgres', 'mysql',
            'mongodb', 'cassandra', 'influxdb', 'prometheus', 'grafana',
            
            # Cloud service domains
            'amazonaws.com', 'cloudfront.net', 's3.amazonaws.com',
            'rds.amazonaws.com', 'elasticbeanstalk.com', 'ec2.amazonaws.com',
            'googleapis.com', 'googleusercontent.com', 'cloud.google.com',
            'azure.com', 'microsoft.com', 'windows.net', 'cloudapp.net',
            'herokuapp.com', 'netlify.app', 'vercel.app', 'github.io',
            'gitlab.io', 'bitbucket.io', 'surge.sh', 'now.sh',
            
            # Common subdomains
            'api.', 'www.', 'mail.', 'smtp.', 'pop.', 'imap.', 'ftp.',
            'ssh.', 'dns.', 'ns1.', 'ns2.', 'mx.', 'web.', 'app.',
            'db.', 'redis.', 'elasticsearch.', 'kafka.', 'rabbitmq.',
            'postgres.', 'mysql.', 'mongodb.', 'cassandra.', 'influxdb.',
            'prometheus.', 'grafana.', 'dev.', 'test.', 'staging.',
            'prod.', 'uat.', 'qa.', 'preview.', 'demo.', 'sandbox.'
        ]
        
        # Check if value contains hostname patterns
        # But exclude known secret patterns that might contain hostname-like strings
        if any(pattern in value_lower for pattern in hostname_patterns):
            # Skip if this looks like a known secret pattern
            if self.is_likely_secret_pattern(value):
                return False
            return True
        
        # IP address patterns (IPv4 and IPv6)
        ip_patterns = [
            r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$',  # IPv4
            r'^[0-9a-fA-F:]+$',  # IPv6 (simplified)
            r'^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$',  # Private IPv4 ranges
            r'^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$',
            r'^192\.168\.\d{1,3}\.\d{1,3}$'
        ]
        
        for pattern in ip_patterns:
            if re.match(pattern, value):
                return True
        
        # URL-like patterns without schemes
        url_like_patterns = [
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$',  # Domain-like
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*:\d+$',  # Domain with port
            r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*/[a-zA-Z0-9\-_/]*$'  # Domain with path
        ]
        
        for pattern in url_like_patterns:
            if re.match(pattern, value):
                # Skip if this looks like a known secret pattern
                if self.is_likely_secret_pattern(value):
                    return False
                return True
        
        return False
    
    def is_likely_secret_pattern(self, value: str) -> bool:
        """Check if a value looks like a known secret pattern despite containing domain-like strings."""
        value_lower = value.lower()
        
        # AWS Access Key ID pattern (starts with AKIA, AIAK, AGPA, AIDA, ARPA, or AROA)
        if re.match(r'^AKIA[0-9A-Z]{16}$', value):
            return True
        
        # AWS Access Key ID pattern (starts with AKIA, AIAK, AGPA, AIDA, ARPA, or AROA) - case insensitive
        if re.match(r'^AKIA[0-9A-Z]{16}$', value, re.IGNORECASE):
            return True
        
        # AWS Secret Access Key pattern (40 characters, base64-like)
        if re.match(r'^[A-Za-z0-9/+=]{40}$', value):
            return True
        
        # GitHub Personal Access Token patterns
        if re.match(r'^ghp_[0-9a-zA-Z]{36}$', value):
            return True
        if re.match(r'^github_pat_[0-9a-zA-Z]{82}$', value):
            return True
        
        # OpenAI API Key pattern
        if re.match(r'^sk-[0-9a-zA-Z]{48}$', value):
            return True
        
        # JWT Token pattern (three base64 sections separated by dots)
        if re.match(r'^eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+$', value):
            return True
        
        # Generic API key patterns (high entropy, specific length)
        if re.match(r'^[A-Za-z0-9_-]{20,}$', value) and len(value) >= 20:
            # Check if it has high entropy (likely a secret)
            entropy = self.calculate_entropy(value)
            if entropy > 4.0:  # High entropy threshold
                return True
        
        return False
    
    def scan_content(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Scan content for potential secrets."""
        # Initialize a local list to collect secrets found in this content
        content_secrets = []
        lines = content.splitlines()
        
        self.logger.debug(f"Scanning {len(lines)} lines in {file_path}")
        
        for line_num, line in enumerate(lines, 1):
            # Only skip empty lines, but process all comments
            if not line.strip():
                continue
            
            # Check if this line should be skipped for specific file types
            if self.should_skip_terraform_line(line, file_path):
                self.logger.debug(f"Skipping Terraform line {line_num} in {file_path}: contains excluded keywords")
                continue
            
            if self.should_skip_yaml_line(line, file_path):
                self.logger.debug(f"Skipping YAML line {line_num} in {file_path}: contains excluded keywords")
                continue
            
            if self.should_skip_shell_line(line, file_path):
                self.logger.debug(f"Skipping shell line {line_num} in {file_path}: contains excluded keywords")
                continue
            
            # Check if we've already found a secret at this file:line
            file_line_key = (file_path, line_num)
            if file_line_key in self._seen_file_lines:
                self.logger.debug(f"Already found secret at {file_path}:{line_num}, skipping")
                continue
            
            # Flag to track if we found a secret in this line
            found_secret_in_line = False
            
            # First pass: Check against defined patterns
            for pattern, secret_type, config in PATTERNS:
                if found_secret_in_line:
                    break
                
                matches = re.finditer(pattern, line)
                for match in matches:
                    value = match.group(0)
                    # If the pattern specifies a capture group for the value, use it
                    value_group_index = config.get('value_group')
                    if isinstance(value_group_index, int):
                        try:
                            value = match.group(value_group_index)
                        except IndexError:
                            # Fallback to the full match if group is not present
                            value = match.group(0)
                    
                    # Skip common non-secrets
                    if self.should_skip_value(value, file_path):
                        continue
                    
                    # Check minimum length if specified
                    min_length = config.get('min_length', 0)
                    if len(value) < min_length:
                        continue
                    
                    # Calculate entropy if required
                    entropy = None
                    if config.get('require_entropy', True):
                        entropy = self.calculate_entropy(value)
                        threshold = config.get('threshold', ENTROPY_THRESHOLDS['default'])
                        if entropy < threshold:
                            continue
                    
                    # For environment variables, check if the name suggests a secret
                    if config.get('check_name', False) and not self.is_suspicious_env_var(match.group(1)):
                        continue
                    
                    # Record the found secret
                    secret = {
                        'file_path': file_path,
                        'line_number': line_num,
                        'line': line,
                        'matched_content': value,
                        'type': secret_type,
                        'entropy': entropy,
                        'detection_method': 'pattern_match'
                    }
                    content_secrets.append(secret)
                    self._seen_file_lines.add(file_line_key)
                    
                    # Add debug log for found secret
                    self.logger.debug(f"Found secret in {file_path} at line {line_num}: type={secret_type}")
                    
                    found_secret_in_line = True
                    break  # Once we find a secret in this line, no need to check other matches
            
            # If we already found a secret in this line, skip the variable name scanning
            if found_secret_in_line:
                continue
            
            # Second pass: Variable name scanning
            var_patterns = [
                r'(?i)(?:const|let|var|private|public|protected)?\s*(\w+)\s*[=:]\s*["\']([^"\']+)["\']',
                r'(?i)(\w+)\s*[=:]\s*["\']([^"\']+)["\']',
                r'(?i)(\w+)\s*=\s*"""([^"]*)"""',  # Python multi-line strings
                r'(?i)(\w+)\s*=\s*`([^`]*)`',      # Template literals
            ]
            
            for pattern in var_patterns:
                matches = re.finditer(pattern, line)
                for match in matches:
                    var_name, value = match.groups()
                    
                    # Skip common non-secrets
                    if self.should_skip_value(value, file_path):
                        continue
                    
                    # Check if variable name suggests a secret
                    if not self.is_suspicious_env_var(var_name):
                        continue
                    
                    # Calculate entropy
                    entropy = self.calculate_entropy(value)
                    
                    # Use different thresholds based on variable name patterns
                    if 'password' in var_name.lower():
                        threshold = ENTROPY_THRESHOLDS['password']
                    elif 'key' in var_name.lower():
                        # Use very high threshold for generic key patterns to filter out programming terms
                        # like buttonkey, presskey, etc. while still catching real secrets
                        threshold = ENTROPY_THRESHOLDS['generic_key']
                    else:
                        threshold = ENTROPY_THRESHOLDS['default']
                    
                    if entropy >= threshold:
                        secret = {
                            'file_path': file_path,
                            'line_number': line_num,
                            'line': line,
                            'matched_content': value,
                            'type': 'Variable Assignment',
                            'variable_name': var_name,
                            'entropy': entropy,
                            'detection_method': 'variable_scan'
                        }
                        content_secrets.append(secret)
                        self._seen_file_lines.add(file_line_key)
                        
                        # Add debug log for found secret
                        self.logger.debug(f"Found variable secret in {file_path} at line {line_num}: var={var_name}")
                        
                        break
                
                # If we found a secret in this pattern, break out of the pattern loop
                if len(content_secrets) > 0 and content_secrets[-1]['line_number'] == line_num:
                    break
        
        self.logger.debug(f"Completed scan of {file_path}, found {len(content_secrets)} secrets")
        return content_secrets
    
    def scan_file(self, file_path: str) -> List[Dict[str, Union[str, int]]]:
        """Scan a single file for potential secrets."""
        try:
            # Check if the file should be excluded based on the new exclusion rules
            if should_exclude_file(file_path):
                self.logger.debug(f"Skipping excluded file: {file_path}")
                return []
                
            self.logger.debug(f"Starting scan of file: {file_path}")
            
            # Read file content
            cmd = ['git', 'show', f':0:{file_path}']
            try:
                result = run_subprocess(cmd, capture_output=True, text=True, check=True)
                content = result.stdout
                self.logger.debug(f"Read {len(content)} bytes from git for file {file_path}")
            except subprocess.CalledProcessError:
                # File might not be in git yet, try reading directly
                self.logger.debug(f"File {file_path} not in git index, reading directly")
                try:
                    with open(file_path, 'r', encoding='utf-8') as file:
                        content = file.read()
                except UnicodeDecodeError:
                    # Try reading as binary and decoding with 'latin-1'
                    self.logger.debug(f"Unicode decode error for {file_path}, trying latin-1 encoding")
                    with open(file_path, 'r', encoding='latin-1') as file:
                        content = file.read()
                self.logger.debug(f"Read {len(content)} bytes directly from file {file_path}")
            
            # Scan the content
            file_secrets = self.scan_content(content, file_path)
            
            if file_secrets:
                self.logger.debug(f"Found {len(file_secrets)} secrets in {file_path}")
            else:
                self.logger.debug(f"No secrets found in {file_path}")
                
            return file_secrets
        except Exception as e:
            self.logger.error(f"Error scanning file {file_path}: {e}")
            return []

    def scan_files_to_push(self, files_list=None) -> List[Dict[str, Any]]:
        """Scan files that will be pushed for secrets."""
        try:
            # Get list of files to be pushed if not provided
            files_to_push = files_list or []
            
            if not files_to_push:
                # Get list of files to be pushed
                cmd = ['git', 'diff', '--cached', '--name-only']
                result = subprocess.run(cmd, capture_output=True, text=True, check=True)
                files_to_push = result.stdout.strip().split('\n')
                files_to_push = [f for f in files_to_push if f]  # Remove empty strings
                
            self.logger.info(f"Scanning {len(files_to_push)} files to be pushed")
            
            # Filter out excluded file types and directories
            filtered_files = []
            for file_path in files_to_push:
                # Skip files that should be excluded
                if should_exclude_file(file_path):
                    self.logger.debug(f"Skipping excluded file: {file_path}")
                    continue
                filtered_files.append(file_path)
            
            self.logger.info(f"After filtering, scanning {len(filtered_files)} files")
            
            # Scan files
            for file_path in filtered_files:
                file_secrets = self.scan_file(file_path)
                if file_secrets:
                    self.found_secrets.extend(file_secrets)
                    
            return self.found_secrets
        except Exception as e:
            self.logger.error(f"Error scanning files to push: {e}")
            return []
    
    def scan_files(self, files_list: List[str]) -> List[Dict[str, Any]]:
        """Scan a list of files for secrets."""
        if not files_list:
            self.logger.info("No files to scan")
            return []
        
        self.logger.info(f"Scanning {len(files_list)} files")
        
        # Filter out excluded file types and directories
        filtered_files = []
        for file_path in files_list:
            # Skip files that should be excluded
            if should_exclude_file(file_path):
                self.logger.debug(f"Skipping excluded file: {file_path}")
                continue
            filtered_files.append(file_path)
        
        self.logger.info(f"After filtering, scanning {len(filtered_files)} files")
        
        # Scan files
        for file_path in filtered_files:
            file_secrets = self.scan_file(file_path)
            if file_secrets:
                self.found_secrets.extend(file_secrets)
                
        return self.found_secrets
    
    def scan_line(self, file_path: str, line_number: int, line: str) -> None:
        """Scan a single line for potential secrets."""
        file_line_key = (file_path, line_number)
        if file_line_key in self._seen_file_lines:
            return
        
        # Check if the file should be excluded
        if should_exclude_file(file_path):
            self.logger.debug(f"Skipping excluded file line: {file_path}:{line_number}")
            return
        
        # Check if this line should be skipped for specific file types
        if self.should_skip_terraform_line(line, file_path):
            self.logger.debug(f"Skipping Terraform line {line_number} in {file_path}: contains excluded keywords")
            return
        
        if self.should_skip_yaml_line(line, file_path):
            self.logger.debug(f"Skipping YAML line {line_number} in {file_path}: contains excluded keywords")
            return
        
        if self.should_skip_shell_line(line, file_path):
            self.logger.debug(f"Skipping shell line {line_number} in {file_path}: contains excluded keywords")
            return
        
        found_secret = False
        
        # Check against defined patterns
        for pattern, secret_type, config in PATTERNS:
            if found_secret:
                break
            
            matches = re.finditer(pattern, line)
            for match in matches:
                value = match.group(0)
                value_group_index = config.get('value_group')
                if isinstance(value_group_index, int):
                    try:
                        value = match.group(value_group_index)
                    except IndexError:
                        value = match.group(0)
                
                # Skip common non-secrets
                if self.should_skip_value(value, file_path):
                    continue
                
                # Check minimum length if specified
                min_length = config.get('min_length', 0)
                if len(value) < min_length:
                    continue
                
                # Calculate entropy if required
                entropy = None
                if config.get('require_entropy', True):
                    entropy = self.calculate_entropy(value)
                    threshold = config.get('threshold', ENTROPY_THRESHOLDS['default'])
                    if entropy < threshold:
                        continue
                
                # For environment variables, check if the name suggests a secret
                if config.get('check_name', False) and not self.is_suspicious_env_var(match.group(1)):
                    continue
                
                # Record the found secret
                secret = {
                    'file_path': file_path,
                    'line_number': line_number,
                    'line': line,
                    'matched_content': value,
                    'type': secret_type,
                    'entropy': entropy,
                    'detection_method': 'pattern_match'
                }
                self.found_secrets.append(secret)
                self._seen_file_lines.add(file_line_key)
                
                found_secret = True
                break
        
        if found_secret:
            return
        
        # Variable name scanning
        var_patterns = [
            r'(?i)(?:const|let|var|private|public|protected)?\s*(\w+)\s*[=:]\s*["\']([^"\']+)["\']',
            r'(?i)(\w+)\s*[=:]\s*["\']([^"\']+)["\']',
            r'(?i)(\w+)\s*=\s*"""([^"]*)"""',  # Python multi-line strings
            r'(?i)(\w+)\s*=\s*`([^`]*)`',      # Template literals
        ]
        
        for pattern in var_patterns:
            matches = re.finditer(pattern, line)
            for match in matches:
                var_name, value = match.groups()
                
                # Skip common non-secrets
                if self.should_skip_value(value, file_path):
                    continue
                
                # Check if variable name suggests a secret
                if not self.is_suspicious_env_var(var_name):
                    continue
                
                # Calculate entropy
                entropy = self.calculate_entropy(value)
                
                # Use different thresholds based on variable name patterns
                if 'password' in var_name.lower():
                    threshold = ENTROPY_THRESHOLDS['password']
                elif 'key' in var_name.lower():
                    # Use very high threshold for generic key patterns to filter out programming terms
                    # like buttonkey, presskey, etc. while still catching real secrets
                    threshold = ENTROPY_THRESHOLDS['generic_key']
                else:
                    threshold = ENTROPY_THRESHOLDS['default']
                
                if entropy >= threshold:
                    secret = {
                        'file_path': file_path,
                        'line_number': line_number,
                        'line': line,
                        'matched_content': value,
                        'type': 'Variable Assignment',
                        'variable_name': var_name,
                        'entropy': entropy,
                        'detection_method': 'variable_scan'
                    }
                    self.found_secrets.append(secret)
                    self._seen_file_lines.add(file_line_key)
                    break
            
            if file_line_key in self._seen_file_lines:
                break
    
    def scan_repository(self) -> List[Dict[str, Union[str, int]]]:
        """Scan the entire repository for secrets."""
        try:
            self.logger.info("Starting repository scan")
            
            # Get all tracked files
            cmd = ['git', 'ls-files']
            
            result = run_subprocess(cmd, capture_output=True, text=True, check=True)
            files = result.stdout.strip().split('\n')
            files = [f for f in files if f]  # Remove empty strings
            
            self.logger.info(f"Found {len(files)} tracked files in repository")
            
            # Filter out excluded file types and directories
            filtered_files = []
            for file_path in files:
                # Skip files that should be excluded
                if should_exclude_file(file_path):
                    self.logger.debug(f"Skipping excluded file: {file_path}")
                    continue
                filtered_files.append(file_path)
            
            self.logger.info(f"After filtering, scanning {len(filtered_files)} files")
            
            # Scan files
            for file_path in filtered_files:
                file_secrets = self.scan_file(file_path)
                if file_secrets:
                    self.found_secrets.extend(file_secrets)
                    
            return self.found_secrets
        except Exception as e:
            self.logger.error(f"Error scanning repository: {e}")
            return []

    def scan_changed_lines(self, files_list: List[str]) -> List[Dict[str, Any]]:
        """Scan only the changed lines in files for secrets.
        
        This method uses git diff to identify only the changed lines in the files
        and scans only those specific lines, rather than the entire file content.
        """
        if not files_list:
            self.logger.info("No files to scan")
            return []
        
        self.logger.info(f"Scanning changed lines in {len(files_list)} files")
        
        # Get git diff information to identify changed lines
        changed_lines = get_git_diff()
        
        # If we couldn't get changed lines (not a git repo or other issue),
        # fall back to scanning entire files
        if not changed_lines:
            self.logger.info("Could not determine changed lines, falling back to full file scan")
            return self.scan_files(files_list)
        
        # Filter out excluded file types and directories
        filtered_files = []
        for file_path in files_list:
            # Skip files that should be excluded
            if should_exclude_file(file_path):
                self.logger.debug(f"Skipping excluded file: {file_path}")
                continue
            filtered_files.append(file_path)
        
        self.logger.info(f"After filtering, scanning changed lines in {len(filtered_files)} files")
        
        # Scan only the changed lines in each file
        for file_path in filtered_files:
            # If the file is in our changed_lines dict, scan only those lines
            if file_path in changed_lines:
                print(f"-  Scanning {len(changed_lines[file_path])} changed lines in {file_path}")
                for line_number, line_content in changed_lines[file_path]:
                    self.scan_line(file_path, line_number, line_content)
            else:
                # If the file is not in changed_lines but still in our files list,
                # it might be a new file - scan it completely
                self.logger.debug(f"File {file_path} not found in diff, scanning entire file")
                file_secrets = self.scan_file(file_path)
                if file_secrets:
                    self.found_secrets.extend(file_secrets)
                    
        return self.found_secrets

def generate_html_report(output_path: str, **kwargs) -> bool:
    """Generate an HTML report with diff scan and repo scan results."""
    try:
        diff_secrets = kwargs.get('diff_secrets', [])
        repo_secrets = kwargs.get('repo_secrets', [])
        
        # Enhanced logging to show exact counts and details
        logging.info(f"Generating HTML report with {len(diff_secrets)} diff secrets and {len(repo_secrets)} repo secrets")
        logging.debug(f"Raw diff_secrets count: {len(diff_secrets)}")
        logging.debug(f"Raw repo_secrets count: {len(repo_secrets)}")
        
        if repo_secrets:
            # Log some details about repository secrets to help diagnose issues
            logging.debug("Repository secrets summary:")
            file_counts = {}
            for s in repo_secrets:
                file_path = s.get('file_path', 'unknown')
                file_counts[file_path] = file_counts.get(file_path, 0) + 1
            
            for file_path, count in file_counts.items():
                logging.debug(f"  - {file_path}: {count} secrets")
        else:
            logging.debug("No repository secrets provided to HTML report generator")
        
        # Deduplicate secrets for diff display based on file+line
        diff_seen = set()
        unique_diff_secrets = []
        
        for secret in diff_secrets:
            key = (secret.get('file_path', ''), secret.get('line_number', 0))
            if key not in diff_seen:
                diff_seen.add(key)
                unique_diff_secrets.append(secret)
        
        # For repository scan, deduplicate based on file+line
        repo_seen = set()
        unique_repo_secrets = []
        
        for secret in repo_secrets:
            key = (secret.get('file_path', ''), secret.get('line_number', 0))
            if key not in repo_seen:
                repo_seen.add(key)
                unique_repo_secrets.append(secret)
        
        # Use the deduplicated lists
        diff_secrets = unique_diff_secrets
        repo_secrets = unique_repo_secrets
        
        # Log after deduplication
        logging.debug(f"After deduplication: {len(diff_secrets)} diff secrets, {len(repo_secrets)} repo secrets")
        
        git_metadata = get_git_metadata()
        
        # Generate table rows
        diff_secrets_table_rows = generate_table_rows(diff_secrets)
        repo_secrets_table_rows = generate_table_rows(repo_secrets)
        
        # Log row generation results
        logging.debug(f"Generated {diff_secrets_table_rows.count('<tr>') if diff_secrets_table_rows else 0} diff secret table rows")
        logging.debug(f"Generated {repo_secrets_table_rows.count('<tr>') if repo_secrets_table_rows else 0} repo secret table rows")
        
        # Empty disallowed files section
        disallowed_files_section = ""

        # Get the secret_scan directory (current directory since files will be in secret_scan/)
        secret_scan_dir = Path(__file__).parent
        template_path = secret_scan_dir / "templates" / "report.html"
        
        if not template_path.exists():
            # If template doesn't exist, use a simple built-in template
            logging.warning(f"Template file not found at {template_path}, using built-in template")
            html_content = generate_simple_html_report(diff_secrets, repo_secrets, git_metadata)
        else:
            try:
                # Read and fix the template
                with open(template_path, 'r', encoding='utf-8') as f:
                    template = f.read()
                
                # Replace any problematic format markers in the template with their actual values
                # This fixes issues like the 'margin-top' error
                template = template.replace('{margin-top}', 'margin-top')
                template = template.replace('\n            margin-top', 'margin-top')
                
                # Format the HTML content with values
                disclaimer_text = """<div class="disclaimer">
            <h3>⚠️ DISCLAIMER</h3>
            <p>This tool identifies potential code secrets through regex, dictionary comparisons, and entropy analysis. Despite efforts to accurately pinpoint high-risk exposures, results may contain false positives or overlook certain secrets. Users should apply discretion and judgement when assessing scan results. It is the user's duty to verify and manage flagged content appropriately.</p>
        </div>"""
                
                format_args = {
                    'title': HTML_CONFIG['title'],
                    'primary_color': HTML_CONFIG['styles']['primary_color'],
                    'error_color': HTML_CONFIG['styles']['error_color'],
                    'background_color': HTML_CONFIG['styles']['background_color'],
                    'container_background': HTML_CONFIG['styles']['container_background'],
                    'header_background': HTML_CONFIG['styles']['header_background'],
                    'git_metadata': git_metadata,
                    'diff_secrets_table_rows': diff_secrets_table_rows,
                    'repo_secrets_table_rows': repo_secrets_table_rows,
                    'disallowed_files_section': disallowed_files_section,
                    'disclaimer': disclaimer_text
                }
                
                # Add fallback for common missing keys
                for key in ['margin-top', 'tab-content', 'tab-button']:
                    if key not in format_args:
                        format_args[key] = key
                
                html_content = template.format(**format_args)
            except (KeyError, ValueError) as e:
                # If template formatting fails, fall back to simple report
                # logging.error(f"Error formatting template: {e}, falling back to simple template")
                html_content = generate_simple_html_report(diff_secrets, repo_secrets, git_metadata)

        # Ensure output directory exists
        output_dir = os.path.dirname(output_path)
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        # Write HTML content to file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        logging.info(f"HTML report generated at {output_path}")
        return True
        
    except Exception as e:
        logging.error(f"Error generating HTML report: {e}", exc_info=True)
        return False

def generate_simple_html_report(diff_secrets, repo_secrets, git_metadata):
    """Generate a simple HTML report without relying on a template file."""
    # Format git metadata values safely
    safe_metadata = {
        'author': html.escape(git_metadata.get('author', 'Unknown')),
        'repo_name': html.escape(git_metadata.get('repo_name', 'Unknown')),
        'branch': html.escape(git_metadata.get('branch', 'Unknown')),
        'commit_hash': html.escape(git_metadata.get('commit_hash', 'Unknown')),
        'timestamp': html.escape(git_metadata.get('timestamp', 'Unknown'))
    }
    
    # Generate table rows for diff secrets and repo secrets
    diff_secrets_table_rows = generate_table_rows(diff_secrets)
    repo_secrets_table_rows = generate_table_rows(repo_secrets)
    
    # Create HTML template with tab buttons and styling
    html_content = """<!DOCTYPE html>
<html>
<head>
    <title>Secret Scan Report</title>
    <style>
        body {{ font-family: -apple-system, system-ui, sans-serif; margin: 20px; background: #f8f9fa; }}
        .container {{ max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }}
        h1, h2 {{ color: #0056b3; }}
        .header-info {{ background: #f1f8ff; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 4px solid #0056b3; }}
        .header-info p {{ margin: 5px 0; color: #666; }}
        .header-info strong {{ color: #333; margin-right: 5px; }}
        .disclaimer {{ background: #fff3cd; padding: 15px; border-radius: 5px; margin-bottom: 20px; border-left: 4px solid #ffc107; border: 1px solid #ffeaa7; }}
        .disclaimer h3 {{ color: #856404; margin-top: 0; margin-bottom: 10px; }}
        .disclaimer p {{ margin: 0; color: #856404; font-weight: 500; line-height: 1.5; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 20px; }}
        th, td {{ padding: 12px; text-align: left; border: 1px solid #ddd; }}
        th {{ background: #0056b3; color: white; }}
        tr:nth-child(even) {{ background-color: #f5f5f5; }}
        .secret-content {{ color: #d32f2f; font-family: monospace; white-space: pre-wrap; }}
        .tab-container {{ margin-top: 20px; }}
        .tab-buttons {{ display: flex; gap: 10px; margin-bottom: 20px; }}
        .tab-button {{ padding: 10px 20px; background-color: #f0f0f0; border: none; border-radius: 5px; cursor: pointer; }}
        .tab-button.active {{ background-color: #0056b3; color: white; }}
        .tab-content {{ display: none; }}
        .tab-content.active {{ display: block; }}
        .actions {{ display: flex; justify-content: space-between; align-items: center; margin: 20px 0; }}
        .btn {{ 
            background-color: #0056b3; 
            color: white; 
            border: none; 
            padding: 10px 20px; 
            border-radius: 5px; 
            cursor: pointer; 
            font-size: 16px; 
            text-decoration: none;
            display: inline-flex;
            align-items: center;
        }}
        .btn:hover {{ background-color: #004494; }}
        .icon {{ margin-right: 8px; }}
    </style>
</head>
<body>
    <div class="container">
        <div class="actions">
            <h1>Secret Scan Report</h1>
            <button onclick="window.print()" class="btn">
                <span class="icon">📥</span> Save as PDF
            </button>
        </div>
        
        <div class="header-info">
            <p><strong>Git Author:</strong> {author}</p>
            <p><strong>Repository:</strong> {repo_name}</p>
            <p><strong>Branch:</strong> {branch}</p>
            <p><strong>Commit Hash:</strong> {commit_hash}</p>
            <p><strong>Timestamp:</strong> {timestamp}</p>
        </div>

        <div class="disclaimer">
            <h3>⚠️ DISCLAIMER</h3>
            <p>This tool identifies potential code secrets through regex, dictionary comparisons, and entropy analysis. Despite efforts to accurately pinpoint high-risk exposures, results may contain false positives or overlook certain secrets. Users should apply discretion and judgement when assessing scan results. It is the user's duty to verify and manage flagged content appropriately.</p>
        </div>

        <div class="tab-container">
            <div class="tab-buttons">
                <button class="tab-button active" onclick="showTab('diff-scan')">Push Scan Results</button>
                <button class="tab-button" onclick="showTab('repo-scan')">Repository Scan Results</button>
            </div>

            <div id="diff-scan" class="tab-content active">
                <h2>Files to be Pushed - Secrets Found: {diff_secrets_count}</h2>
                <table>
                    <tr>
                        <th style="width:5%">S.No</th>
                        <th style="width:25%">Filename</th>
                        <th style="width:10%">Line #</th>
                        <th style="width:60%">Secret</th>
                    </tr>
                    {diff_secrets_rows}
                </table>
            </div>

            <div id="repo-scan" class="tab-content">
                <h2>Repository Scan - Secrets Found: {repo_secrets_count}</h2>
                <table>
                    <tr>
                        <th style="width:5%">S.No</th>
                        <th style="width:25%">Filename</th>
                        <th style="width:10%">Line #</th>
                        <th style="width:60%">Secret</th>
                    </tr>
                    {repo_secrets_rows}
                </table>
            </div>
        </div>
    </div>
    
    <script>
        function showTab(tabId) {{
            // Hide all tab contents
            const tabContents = document.querySelectorAll('.tab-content');
            tabContents.forEach(tab => tab.classList.remove('active'));
            
            // Remove active class from all buttons
            const tabButtons = document.querySelectorAll('.tab-button');
            tabButtons.forEach(button => button.classList.remove('active'));
            
            // Show the selected tab
            document.getElementById(tabId).classList.add('active');
            
            // Add active class to the clicked button
            event.target.classList.add('active');
        }}
        
        // Print setup - show both tabs when printing
        window.onbeforeprint = function() {{
            document.querySelectorAll('.tab-content').forEach(tab => {{
                tab.style.display = 'block';
            }});
        }};
        
        window.onafterprint = function() {{
            // Restore tab visibility after printing
            document.querySelectorAll('.tab-content').forEach(tab => {{
                if (tab.classList.contains('active')) {{
                    tab.style.display = 'block';
                }} else {{
                    tab.style.display = 'none';
                }}
            }});
        }};
    </script>
</body>
</html>"""

    # Replace placeholders with actual values
    formatted_html = html_content.format(
        author=safe_metadata['author'],
        repo_name=safe_metadata['repo_name'],
        branch=safe_metadata['branch'],
        commit_hash=safe_metadata['commit_hash'],
        timestamp=safe_metadata['timestamp'],
        diff_secrets_count=len(diff_secrets),
        repo_secrets_count=len(repo_secrets),
        diff_secrets_rows=diff_secrets_table_rows or "<tr><td colspan='4'>No secrets found in files to be pushed</td></tr>",
        repo_secrets_rows=repo_secrets_table_rows or "<tr><td colspan='4'>No secrets found in repository scan</td></tr>"
    )
    
    return formatted_html

def generate_table_rows(secrets):
    """Generate HTML table rows for secrets."""
    rows = []
    for i, s in enumerate(secrets, 1):
        row = "<tr>"
        row += f"<td>{i}</td>"
        row += f"<td>{html.escape(s.get('file_path', ''))}</td>"
        row += f"<td>{s.get('line_number', '')}</td>"
        row += f"<td><div class=\"secret-content\">{html.escape(mask_secret(s.get('line', '')))}</div></td>"
        row += "</tr>"
        rows.append(row)
    return ''.join(rows) if rows else ""

def main() -> None:
    """Main entry point for the secret scanner."""
    # Set up logging
    setup_logging("secret_scan.log")
    
    args = sys.argv[1:]
    scanner = SecretScanner()
    
    # Initialize variables to store results
    repo_results = []
    diff_results = []
    
    # Always scan the repository first
    logging.info("Scanning entire repository...")
    try:
        repo_results = scanner.scan_repository()
        if repo_results:
            print(f"Found {len(repo_results)} potential secrets in repository")
            logging.debug(f"Repository scan returned {len(repo_results)} secrets")
        else:
            logging.info("No secrets found in repository scan")
    except Exception as e:
        logging.error(f"Error scanning repository: {e}")
        sys.exit(1)
    
    # If --diff flag is present, also scan files to be pushed
    if "--diff" in args:
        logging.info("Scanning files to be pushed...")
        try:
            diff_results = scanner.scan_files_to_push()
            if diff_results:
                print(f"Found {len(diff_results)} potential secrets in files to be pushed")
                logging.debug(f"Diff scan returned {len(diff_results)} secrets")
            else:
                logging.info("No secrets found in files to be pushed")
        except Exception as e:
            logging.error(f"Error scanning files to be pushed: {e}")
            sys.exit(1)
    
    # Verify we have the expected data
    logging.debug(f"Before report generation: repo_results={len(repo_results)}, diff_results={len(diff_results)}")
    
    # Generate HTML report with both sets of results
    try:
        output_path = "secret_scan_report.html"
        success = generate_html_report(
            output_path,
            diff_secrets=diff_results,
            repo_secrets=repo_results
        )
        
        if success:
            print(f"HTML report generated at {output_path}")
            print(f"Repository secrets: {len(repo_results)}, Diff secrets: {len(diff_results)}")
        else:
            print("Failed to generate HTML report")
    except Exception as e:
        logging.error(f"Error generating HTML report: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main()