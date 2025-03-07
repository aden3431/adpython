"""
User Management Module for Active Directory.
This module provides functionality for creating and editing users in Active Directory.
"""

import sys
import os

# Add parent directory to path to access root helpers.py
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import from root helpers.py
from helpers import domain_to_base_dn, auto_generate_sam_account, encode_password, get_app_stylesheet

# Enum for operation mode
from enum import Enum, auto
class UserOperation(Enum):
    CREATE = auto()
    EDIT = auto()

# Import module components
from .user_window import UserWindow
from .templates import UserTemplate, TemplateManager
from .attributes_tab import AttributesTab
from .groups_tab import GroupsTab

__all__ = [
    'UserWindow',
    'UserOperation',
    'UserTemplate',
    'TemplateManager',
    'AttributesTab',
    'GroupsTab'
]