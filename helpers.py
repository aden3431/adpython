"""
Helper functions and shared utilities for the AD Management Tool
"""
from ldap3 import Connection, SUBTREE

def domain_to_base_dn(domain: str) -> str:
    """
    Convert a full DNS domain (e.g., 'corp.adenshomelab.xyz') into a base DN.
    E.g., 'corp.adenshomelab.xyz' -> 'DC=corp,DC=adenshomelab,DC=xyz'
    """
    parts = domain.split('.')
    return ','.join(f"DC={part}" for part in parts)


def check_sam_account_exists(sam_account: str, ldap_conn: Connection) -> bool:
    """
    Check if a SAM account with the given name exists in the enterprise.
    Uses an empty search base to search the entire forest.
    
    Args:
        sam_account: The SAM account name to check
        ldap_conn: An active LDAP connection
        
    Returns:
        bool: True if the account exists, False otherwise
    """
    try:
        ldap_conn.search(search_base="", search_filter=f"(sAMAccountName={sam_account})",
                         search_scope=SUBTREE, attributes=["sAMAccountName"])
        return bool(ldap_conn.entries)
    except Exception:
        return False


def auto_generate_sam_account(first: str, last: str, ldap_conn: Connection) -> str:
    """
    Generate candidate SAM account names (all lowercase) based on first and last names.
    Return the first candidate that is ≤20 characters and not already in use.
    
    Uses these patterns:
      1. firstname.lastname
      2. firstinitial.lastname
      3. firsttwoinitials.lastname
      
    Args:
        first: First name
        last: Last name
        ldap_conn: An active LDAP connection
        
    Returns:
        str: A valid SAM account name or None if no valid name can be generated
    """
    first = first.lower().strip()
    last = last.lower().strip()
    candidates = []
    
    # Candidate 1: firstname.lastname
    cand1 = f"{first}.{last}"
    if len(cand1) <= 20:
        candidates.append(cand1)
    
    # Candidate 2: firstinitial.lastname
    cand2 = f"{first[0]}.{last}" if first else ""
    if cand2 and len(cand2) <= 20 and cand2 not in candidates:
        candidates.append(cand2)
    
    # Candidate 3: firsttwoinitials.lastname
    cand3 = f"{first[:2]}.{last}" if len(first) >= 2 else cand2
    if cand3 and len(cand3) <= 20 and cand3 not in candidates:
        candidates.append(cand3)
    
    # Check each candidate against the directory
    for candidate in candidates:
        if not check_sam_account_exists(candidate, ldap_conn):
            return candidate
    
    return None


def encode_password(password: str) -> bytes:
    """
    Properly encode password for Active Directory
    
    Args:
        password: The plain text password
        
    Returns:
        bytes: The encoded password ready for LDAP
    """
    password = '"{}"'.format(password)
    return password.encode('utf-16-le')


def get_app_stylesheet() -> str:
    """
    Returns the application's stylesheet for a modern look
    
    Returns:
        str: CSS stylesheet for the application
    """
    return """
    QWidget {
        font-family: 'Segoe UI', Arial, sans-serif;
        font-size: 10pt;
    }
    
    QMainWindow, QDialog, QWidget#centralWidget {
        background-color: #f5f5f7;
    }
    
    QLabel {
        color: #333;
    }
    
    QLineEdit, QComboBox, QSpinBox {
        padding: 8px;
        border: 1px solid #ccc;
        border-radius: 4px;
        background-color: white;
    }
    
    QLineEdit:focus, QComboBox:focus {
        border: 1px solid #4a86e8;
    }
    
    QPushButton {
        background-color: #4a86e8;
        color: white;
        border: none;
        padding: 8px 16px;
        border-radius: 4px;
        font-weight: bold;
    }
    
    QPushButton:hover {
        background-color: #3b78de;
    }
    
    QPushButton:pressed {
        background-color: #2d5bb9;
    }
    
    QPushButton#secondaryButton {
        background-color: #f0f0f0;
        color: #333;
        border: 1px solid #ccc;
    }
    
    QPushButton#secondaryButton:hover {
        background-color: #e6e6e6;
    }
    
    QTreeWidget, QTableWidget {
        border: 1px solid #ddd;
        border-radius: 4px;
        background-color: white;
    }
    
    QTreeWidget::item, QTableWidget::item {
        padding: 4px;
    }
    
    QTreeWidget::item:selected, QTableWidget::item:selected {
        background-color: #e7f0fd;
        color: #333;
    }
    
    QHeaderView::section {
        background-color: #f0f0f0;
        padding: 6px;
        border: none;
        border-right: 1px solid #ddd;
        border-bottom: 1px solid #ddd;
    }
    
    QGroupBox {
        font-weight: bold;
        border: 1px solid #ddd;
        border-radius: 4px;
        margin-top: 12px;
        padding-top: 16px;
    }
    
    QGroupBox::title {
        subcontrol-origin: margin;
        subcontrol-position: top left;
        left: 10px;
        padding: 0 5px;
    }
    
    QStatusBar {
        background-color: #f0f0f0;
        color: #555;
    }
    
    QSplitter::handle {
        background-color: #ddd;
    }
    
    QTabWidget::pane {
        border: 1px solid #ddd;
        border-radius: 4px;
        background-color: white;
    }
    
    QTabBar::tab {
        background-color: #f0f0f0;
        border: 1px solid #ddd;
        border-bottom: none;
        border-top-left-radius: 4px;
        border-top-right-radius: 4px;
        padding: 8px 12px;
        margin-right: 2px;
    }
    
    QTabBar::tab:selected {
        background-color: white;
        border-bottom: 1px solid white;
    }
    
    QCheckBox {
        spacing: 8px;
    }
    
    QCheckBox::indicator {
        width: 16px;
        height: 16px;
    }
    
    /* Search bar styling */
    QLineEdit#searchBar {
        padding: 8px 8px 8px 30px;
        border: 1px solid #ccc;
        border-radius: 16px;
        background-color: white;
    }
    
    QFrame#separator {
        background-color: #ddd;
    }
    """