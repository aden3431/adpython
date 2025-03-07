"""
Helper functions for Active Directory user management.
"""

import os
import ssl
import random
import string
from enum import Enum, auto
from ldap3 import SUBTREE


def domain_to_base_dn(domain: str) -> str:
    """
    Convert a domain name to a base DN.
    Example: 'example.com' -> 'DC=example,DC=com'
    
    Args:
        domain: Domain name in FQDN format
        
    Returns:
        Base DN string
    """
    parts = domain.split('.')
    return ','.join(f"DC={part}" for part in parts)


def encode_password(password):
    """
    Encode password for LDAP operations according to AD requirements.
    
    Args:
        password: Plain text password
        
    Returns:
        UTF-16LE encoded password with double quotes
    """
    password = '"{}"'.format(password)
    return password.encode('utf-16-le')


def auto_generate_sam_account(first, last, ldap_conn, max_attempts=5):
    """
    Generate a SAM account name based on first and last name.
    Checks Active Directory to ensure the account name is unique.
    
    Args:
        first: First name
        last: Last name
        ldap_conn: Active LDAP connection
        max_attempts: Maximum number of attempts to generate a unique name
        
    Returns:
        A unique SAM account name, or None if couldn't generate one
    """
    if not first or not last or not ldap_conn:
        return None
        
    # Create base candidate (first initial + last name)
    first = first.strip().lower()
    last = last.strip().lower()
    candidate = f"{first[0]}.{last}"
    
    # Ensure it's not too long (20 chars max for legacy compatibility)
    if len(candidate) > 20:
        candidate = candidate[:20]
    
    # Remove any special characters and replace spaces
    valid_chars = string.ascii_lowercase + string.digits + ".-_"
    candidate = ''.join(c if c in valid_chars else '.' for c in candidate)
    
    # Check if the candidate name exists
    if not is_sam_account_unique(ldap_conn, candidate):
        # Try some variations
        for attempt in range(1, max_attempts + 1):
            if attempt <= 2:
                # Try with numbers at the end
                new_candidate = f"{candidate[:19-len(str(attempt))]}{attempt}"
            else:
                # Try with first two chars of first name
                if len(first) >= 2:
                    new_candidate = f"{first[:2]}.{last}"[:20]
                    if not is_sam_account_unique(ldap_conn, new_candidate):
                        # Add a number to the two-char version
                        suffix = attempt - 2
                        new_candidate = f"{first[:2]}.{last[:17-len(str(suffix))]}{suffix}"
                else:
                    # Fall back to adding more numbers
                    new_candidate = f"{candidate[:19-len(str(attempt))]}{attempt}"
            
            if is_sam_account_unique(ldap_conn, new_candidate):
                return new_candidate
        
        # Couldn't find a unique name within the attempt limit
        return None
    
    return candidate


def is_sam_account_unique(ldap_conn, sam_account):
    """
    Check if a SAM account name is unique in Active Directory.
    
    Args:
        ldap_conn: Active LDAP connection
        sam_account: SAM account name to check
        
    Returns:
        True if the account name doesn't exist, False otherwise
    """
    if not ldap_conn or not sam_account:
        return False
    
    try:
        # Search for the account in AD
        search_filter = f"(sAMAccountName={sam_account})"
        ldap_conn.search(
            search_base=ldap_conn.server.info.other['defaultNamingContext'][0],
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=['sAMAccountName']
        )
        
        # If entries found, account exists
        return len(ldap_conn.entries) == 0
    except Exception:
        # On error, assume it's not unique to be safe
        return False


def get_app_stylesheet():
    """
    Returns the application stylesheet for consistent UI styling.
    
    Returns:
        CSS stylesheet as string
    """
    return """
    QWidget {
        font-family: Segoe UI, Arial, sans-serif;
        font-size: 10pt;
    }
    
    QGroupBox {
        font-weight: bold;
        border: 1px solid #ccc;
        border-radius: 5px;
        margin-top: 1ex;
        padding: 10px;
    }
    
    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        padding: 0 3px;
        color: #333;
    }
    
    QPushButton {
        background-color: #f0f0f0;
        border: 1px solid #ccc;
        border-radius: 4px;
        padding: 6px 12px;
        min-width: 80px;
    }
    
    QPushButton:hover {
        background-color: #e0e0e0;
        border-color: #aaa;
    }
    
    QPushButton:pressed {
        background-color: #d0d0d0;
    }
    
    QPushButton#secondaryButton {
        background-color: #f8f8f8;
        color: #444;
    }
    
    QLineEdit, QTextEdit, QComboBox {
        border: 1px solid #aaa;
        border-radius: 3px;
        padding: 4px 8px;
        background-color: white;
        min-height: 24px;
    }
    
    QLineEdit:focus, QTextEdit:focus, QComboBox:focus {
        border-color: #4a90e2;
    }
    
    QLabel {
        color: #333;
    }
    
    QTableWidget {
        gridline-color: #ddd;
        selection-background-color: #e0e0e0;
        selection-color: #333;
        border: 1px solid #ccc;
    }
    
    QTableWidget::item {
        padding: 4px 8px;
        min-height: 22px;
    }
    
    QHeaderView::section {
        background-color: #f5f5f5;
        border: 1px solid #ddd;
        padding: 4px;
        font-weight: bold;
    }
    
    QTabWidget::pane {
        border: 1px solid #ccc;
        background-color: white;
    }
    
    QTabBar::tab {
        background-color: #f0f0f0;
        border: 1px solid #ccc;
        border-bottom-color: #ccc;
        border-top-left-radius: 4px;
        border-top-right-radius: 4px;
        min-width: 100px;
        padding: 6px 10px;
        margin-right: 3px;
    }
    
    QTabBar::tab:selected {
        background-color: white;
        border-bottom-color: white;
    }
    
    QTabBar::tab:hover:!selected {
        background-color: #e0e0e0;
    }
    
    QScrollBar:vertical {
        border: none;
        background-color: #f0f0f0;
        width: 12px;
        margin: 15px 0 15px 0;
    }
    
    QScrollBar::handle:vertical {
        background-color: #c0c0c0;
        min-height: 30px;
        border-radius: 6px;
        margin: 3px;
    }
    
    QScrollBar::handle:vertical:hover {
        background-color: #a0a0a0;
    }
    
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
        border: none;
        background: none;
        height: 15px;
        subcontrol-position: bottom;
        subcontrol-origin: margin;
    }
    
    QCheckBox {
        spacing: 10px;
    }
    
    QCheckBox::indicator {
        width: 18px;
        height: 18px;
    }
    """


class UserOperation(Enum):
    """Enum to distinguish between create and edit operations"""
    CREATE = auto()
    EDIT = auto()