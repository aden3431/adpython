"""
Main window for Active Directory user management (create or edit).
"""

import sys
import os
from PyQt6.QtWidgets import (
    QWidget, QLabel, QLineEdit, QPushButton, QComboBox,
    QVBoxLayout, QHBoxLayout, QMessageBox, QFormLayout, QCheckBox,
    QGroupBox, QTabWidget, QInputDialog, QFileDialog, QDialog, QTextEdit,QListWidget,QApplication
)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QFont
from ldap3 import Server, Connection, MODIFY_REPLACE, MODIFY_ADD, MODIFY_DELETE
from ldap3.core.exceptions import LDAPException

from .helpers import domain_to_base_dn, auto_generate_sam_account, encode_password
from . import UserOperation
from .templates import TemplateManager, UserTemplate
from .attributes_tab import AttributesTab
from .groups_tab import GroupsTab


class UserWindow(QWidget):
    """
    Window for creating or editing an Active Directory user.
    Can be used in either create mode or edit mode.
    """
    # Signal to notify when a user is created or updated
    user_action_completed = pyqtSignal()
    
    def __init__(self, ldap_conn, mode=UserOperation.CREATE, user_dn=None, 
                 ou_list=None, current_domain=None, domains=None):
        """Initialize the user window"""
        super().__init__()
        self.ldap_conn = ldap_conn
        self.mode = mode
        self.user_dn = user_dn
        self.ou_list = ou_list or []
        self.current_domain = current_domain
        self.domains = domains or {}
        self.domain_suffixes = self.discover_domain_suffixes()
        self.base_dn = domain_to_base_dn(current_domain) if current_domain else ""
        self.template_manager = TemplateManager()
        self.user_data = {}
        self.modified_attributes = {}
        
        if self.mode == UserOperation.EDIT:
            self.load_user_data()
            
        self.setup_ui()
    
    def discover_domain_suffixes(self):
        """Get UPN suffixes from domain data"""
        suffixes = []
        
        # Add suffixes from domains dictionary
        for netbios, fqdn in self.domains.items():
            if fqdn:
                suffixes.append(f"@{fqdn}")
                
        # Add current domain
        if self.current_domain and f"@{self.current_domain}" not in suffixes:
            suffixes.append(f"@{self.current_domain}")
            
            # Also add organization domain (corp.com from corp.adenshomelab.com)
            main_domain = '.'.join(self.current_domain.split('.')[-2:])
            if f"@{main_domain}" not in suffixes:
                suffixes.append(f"@{main_domain}")
        
        # Add default if needed
        if not suffixes:
            suffixes.append("@adenshomelab.com")
            
        return sorted(list(set(suffixes)))
    
    def load_user_data(self):
        """Load user data from Active Directory for edit mode"""
        if not self.ldap_conn or not self.user_dn:
            return
            
        try:
            # Get user schema attributes
            schema_attrs = AttributesTab(self.ldap_conn, self.base_dn).get_user_schema_attributes()
            
            # Search for user
            self.ldap_conn.search(
                search_base=self.user_dn,
                search_filter="(objectClass=user)",
                search_scope="BASE",
                attributes=['*']
            )
            
            if not self.ldap_conn.entries:
                QMessageBox.critical(self, "Error", f"User not found: {self.user_dn}")
                self.close()
                return
                
            # Get user data
            user_entry = self.ldap_conn.entries[0]
            
            # Initialize with empty values
            for attr_name in schema_attrs:
                self.user_data[attr_name] = ""
            
            # Fill with actual values
            for attr_name in user_entry.entry_attributes:
                attr_val = getattr(user_entry, attr_name)
                if attr_val.value is None:
                    self.user_data[attr_name] = ""
                elif isinstance(attr_val.value, list):
                    self.user_data[attr_name] = attr_val.value
                else:
                    self.user_data[attr_name] = attr_val.value
                    
        except Exception as e:
            QMessageBox.critical(self, "Error Loading User", f"Failed to load user data: {e}")
            self.close()
    
    def setup_ui(self):
        """Set up the UI based on current mode (create or edit)"""
        print(f"Mode: {self.mode}, CREATE: {UserOperation.CREATE}")
        if self.mode == UserOperation.CREATE:
            self.setWindowTitle("Create New User")
            self.setup_create_mode_ui()
        else:
            self.setWindowTitle("Edit User")
            self.setup_edit_mode_ui()
            
        self.setMinimumWidth(800)
        self.setMinimumHeight(700)
    
    def setup_create_mode_ui(self):
        """Setup UI for create mode"""
        main_layout = QVBoxLayout()
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(25, 25, 25, 25)
        
        # Header section
        title_label = QLabel("Create New User")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(title_label)
        
        subtitle = QLabel("Enter user details below")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(subtitle)
        
        # Template section
        template_section = QGroupBox("Templates")
        template_layout = QHBoxLayout()
        
        template_layout.addWidget(QLabel("User Template:"))
        self.template_combo = QComboBox()
        self.update_template_list()
        template_layout.addWidget(self.template_combo)
        
        load_btn = QPushButton("Load")
        load_btn.clicked.connect(self.load_template)
        template_layout.addWidget(load_btn)
        
        save_btn = QPushButton("Save Current")
        save_btn.clicked.connect(self.save_current_as_template)
        template_layout.addWidget(save_btn)
        
        manage_btn = QPushButton("Manage")
        manage_btn.clicked.connect(self.manage_templates)
        template_layout.addWidget(manage_btn)
        
        template_section.setLayout(template_layout)
        main_layout.addWidget(template_section)
        
        # Tab widget
        tab_widget = QTabWidget()
        
        # Basic Info Tab
        basic_tab = QWidget()
        basic_layout = QVBoxLayout(basic_tab)
        
        # OU Selection
        ou_group = QGroupBox("Organizational Unit")
        ou_form = QFormLayout()
        ou_form.setSpacing(10)
        ou_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        self.ou_combo = QComboBox()
        sorted_ous = sorted(self.ou_list, key=lambda x: x[0])
        for display, ou_dn in sorted_ous:
            self.ou_combo.addItem(display, ou_dn)
            
        ou_form.addRow("Select OU:", self.ou_combo)
        ou_group.setLayout(ou_form)
        basic_layout.addWidget(ou_group)
        
        # Person Info Group
        person_group = QGroupBox("Personal Information")
        person_form = QFormLayout()
        person_form.setSpacing(10)
        person_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        self.first_name_edit = QLineEdit()
        self.last_name_edit = QLineEdit()
        self.display_name_edit = QLineEdit()
        
        person_form.addRow("First Name:", self.first_name_edit)
        person_form.addRow("Last Name:", self.last_name_edit)
        person_form.addRow("Display Name:", self.display_name_edit)
        person_group.setLayout(person_form)
        basic_layout.addWidget(person_group)
        
        # Account Info Group
        account_group = QGroupBox("Account Information")
        account_form = QFormLayout()
        account_form.setSpacing(10)
        account_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        # Contractor checkbox
        self.contractor_chk = QCheckBox("Contractor (adds -c suffix to username)")
        self.contractor_chk.stateChanged.connect(self.update_contractor_status)
        account_form.addRow("", self.contractor_chk)
        
        self.sam_account_edit = QLineEdit()
        
        # UPN with dropdown
        upn_layout = QHBoxLayout()
        self.upn_edit = QLineEdit()
        self.upn_suffix_combo = QComboBox()
        self.upn_suffix_combo.addItems(self.domain_suffixes)
        if self.upn_suffix_combo.count() > 0:
            self.upn_suffix_combo.setCurrentIndex(0)
        upn_layout.addWidget(self.upn_edit)
        upn_layout.addWidget(self.upn_suffix_combo)
        
        # Password fields
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password_edit = QLineEdit()
        self.confirm_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        
        account_form.addRow("SAM Account Name:", self.sam_account_edit)
        account_form.addRow("User Principal Name:", upn_layout)
        account_form.addRow("Password:", self.password_edit)
        account_form.addRow("Confirm Password:", self.confirm_password_edit)
        
        # Password Options
        self.change_password_chk = QCheckBox("User must change password at next logon")
        self.never_expires_chk = QCheckBox("Password never expires")
        self.never_expires_chk.setChecked(True)
        
        account_form.addRow("", self.change_password_chk)
        account_form.addRow("", self.never_expires_chk)
        
        account_group.setLayout(account_form)
        basic_layout.addWidget(account_group)
        basic_layout.addStretch()
        
        # Additional Info Tab
        additional_tab = QWidget()
        additional_layout = QVBoxLayout(additional_tab)
        
        # Job Info
        job_group = QGroupBox("Employment Information")
        job_form = QFormLayout()
        job_form.setSpacing(10)
        job_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        self.job_title_edit = QLineEdit()
        self.department_edit = QLineEdit()
        self.company_edit = QLineEdit()
        
        job_form.addRow("Job Title:", self.job_title_edit)
        job_form.addRow("Department:", self.department_edit)
        job_form.addRow("Company:", self.company_edit)
        job_group.setLayout(job_form)
        additional_layout.addWidget(job_group)
        
        # Address Info
        address_group = QGroupBox("Address Information")
        address_form = QFormLayout()
        address_form.setSpacing(10)
        address_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        self.street_edit = QLineEdit()
        self.city_edit = QLineEdit()
        self.state_edit = QLineEdit()
        self.postal_edit = QLineEdit()
        
        # Country dropdown
        self.country_combo = QComboBox()
        countries = [
            ("United States", "US", "840"),
            ("Canada", "CA", "124"),
            ("United Kingdom", "GB", "826")
        ]
        
        for country_name, country_code, country_num in countries:
            self.country_combo.addItem(country_name, (country_code, country_num))
            
        address_form.addRow("Street Address:", self.street_edit)
        address_form.addRow("City:", self.city_edit)
        address_form.addRow("State/Province:", self.state_edit)
        address_form.addRow("Postal Code:", self.postal_edit)
        address_form.addRow("Country:", self.country_combo)
        
        address_group.setLayout(address_form)
        additional_layout.addWidget(address_group)
        additional_layout.addStretch()
        
        # Create specialized tabs
        self.attributes_tab = AttributesTab(self, self.ldap_conn, self.base_dn)
        self.groups_tab = GroupsTab(self, self.ldap_conn, self.base_dn)
        
        # Add tabs to widget
        tab_widget.addTab(basic_tab, "Basic Info")
        tab_widget.addTab(additional_tab, "Job & Address")
        tab_widget.addTab(self.groups_tab, "Group Membership")
        tab_widget.addTab(self.attributes_tab, "Attributes")
        
        main_layout.addWidget(tab_widget)
        
        # Button row
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setObjectName("secondaryButton")
        self.cancel_button.clicked.connect(self.close)
        button_layout.addWidget(self.cancel_button)
        
        self.create_button = QPushButton("Create User")
        self.create_button.clicked.connect(self.create_user)
        button_layout.addWidget(self.create_button)
        
        main_layout.addLayout(button_layout)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(self.status_label)
        
        self.setLayout(main_layout)

        # Connect signals for real-time updates
        self.first_name_edit.textChanged.connect(self.auto_update_fields)
        self.last_name_edit.textChanged.connect(self.auto_update_fields)
        self.sam_account_edit.textChanged.connect(self.sync_upn_field)
    
    def setup_edit_mode_ui(self):
        """Setup UI for edit mode"""
        main_layout = QVBoxLayout()
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(25, 25, 25, 25)
        
        # Header section with user info
        display_name = self.user_data.get('displayName', 'Unknown User')
        title_label = QLabel(f"Edit User: {display_name}")
        title_font = QFont()
        title_font.setPointSize(14)
        title_font.setBold(True)
        title_label.setFont(title_font)
        title_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(title_label)
        
        subtitle = QLabel(f"Username: {self.user_data.get('sAMAccountName', '')}")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(subtitle)
        
        # Tab widget
        tab_widget = QTabWidget()
        
        # General Tab
        general_tab = QWidget()
        general_layout = QVBoxLayout(general_tab)
        
        # Personal Information
        person_group = QGroupBox("Personal Information")
        person_form = QFormLayout()
        person_form.setSpacing(10)
        person_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        self.first_name_edit = QLineEdit(self.user_data.get('givenName', ''))
        self.last_name_edit = QLineEdit(self.user_data.get('sn', ''))
        self.display_name_edit = QLineEdit(self.user_data.get('displayName', ''))
        self.email_edit = QLineEdit(self.user_data.get('mail', ''))
        self.phone_edit = QLineEdit(self.user_data.get('telephoneNumber', ''))
        self.mobile_edit = QLineEdit(self.user_data.get('mobile', ''))
        
        person_form.addRow("First Name:", self.first_name_edit)
        person_form.addRow("Last Name:", self.last_name_edit)
        person_form.addRow("Display Name:", self.display_name_edit)
        person_form.addRow("Email:", self.email_edit)
        person_form.addRow("Phone:", self.phone_edit)
        person_form.addRow("Mobile:", self.mobile_edit)
        
        person_group.setLayout(person_form)
        general_layout.addWidget(person_group)
        
        # Account Information
        account_group = QGroupBox("Account Information")
        account_form = QFormLayout()
        account_form.setSpacing(10)
        account_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        # SAM Account (read-only)
        self.sam_account_edit = QLineEdit(self.user_data.get('sAMAccountName', ''))
        self.sam_account_edit.setReadOnly(True)
        
        # UPN with suffix
        upn = self.user_data.get('userPrincipalName', '')
        upn_prefix, upn_suffix = upn, ""
        if '@' in upn:
            upn_parts = upn.split('@', 1)
            upn_prefix = upn_parts[0]
            upn_suffix = '@' + upn_parts[1]
        
        upn_layout = QHBoxLayout()
        self.upn_edit = QLineEdit(upn_prefix)
        self.upn_suffix_combo = QComboBox()
        
        # Add current suffix if not in list
        if upn_suffix and upn_suffix not in self.domain_suffixes:
            self.domain_suffixes.append(upn_suffix)
            self.domain_suffixes.sort()
            
        self.upn_suffix_combo.addItems(self.domain_suffixes)
        
        # Select current suffix
        if upn_suffix:
            suffix_idx = self.upn_suffix_combo.findText(upn_suffix)
            if suffix_idx >= 0:
                self.upn_suffix_combo.setCurrentIndex(suffix_idx)
                
        upn_layout.addWidget(self.upn_edit)
        upn_layout.addWidget(self.upn_suffix_combo)
        
        # Account options
        uac = self.user_data.get('userAccountControl', 0)
        self.disabled_chk = QCheckBox("Account is disabled")
        self.disabled_chk.setChecked(bool(uac & 2))  # ADS_UF_ACCOUNTDISABLE
        
        self.pwd_never_expires_chk = QCheckBox("Password never expires")
        self.pwd_never_expires_chk.setChecked(bool(uac & 65536))  # ADS_UF_DONT_EXPIRE_PASSWD
        
        self.cannot_change_pwd_chk = QCheckBox("User cannot change password")
        self.cannot_change_pwd_chk.setChecked(bool(uac & 64))  # ADS_UF_PASSWD_CANT_CHANGE
        
        self.pwd_expired_chk = QCheckBox("User must change password at next logon")
        self.pwd_expired_chk.setChecked(self.user_data.get('pwdLastSet', '') == 0)
        
        # Password reset section
        pwd_group = QGroupBox("Reset Password")
        pwd_group.setCheckable(True)
        pwd_group.setChecked(False)
        pwd_layout = QFormLayout()
        
        self.new_password_edit = QLineEdit()
        self.new_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.confirm_password_edit = QLineEdit()
        self.confirm_password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        
        pwd_layout.addRow("New Password:", self.new_password_edit)
        pwd_layout.addRow("Confirm Password:", self.confirm_password_edit)
        pwd_group.setLayout(pwd_layout)
        
        account_form.addRow("SAM Account Name:", self.sam_account_edit)
        account_form.addRow("User Principal Name:", upn_layout)
        account_form.addRow("", self.disabled_chk)
        account_form.addRow("", self.pwd_never_expires_chk)
        account_form.addRow("", self.cannot_change_pwd_chk)
        account_form.addRow("", self.pwd_expired_chk)
        account_form.addRow("", pwd_group)
        
        account_group.setLayout(account_form)
        general_layout.addWidget(account_group)
        
        # Job Tab
        job_tab = QWidget()
        job_layout = QVBoxLayout(job_tab)
        
        # Employment Info
        job_group = QGroupBox("Employment Information")
        job_form = QFormLayout()
        job_form.setSpacing(10)
        job_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        self.job_title_edit = QLineEdit(self.user_data.get('title', ''))
        self.department_edit = QLineEdit(self.user_data.get('department', ''))
        self.company_edit = QLineEdit(self.user_data.get('company', ''))
        self.description_edit = QLineEdit(self.user_data.get('description', ''))
        
        job_form.addRow("Job Title:", self.job_title_edit)
        job_form.addRow("Department:", self.department_edit)
        job_form.addRow("Company:", self.company_edit)
        job_form.addRow("Description:", self.description_edit)
        
        job_group.setLayout(job_form)
        job_layout.addWidget(job_group)
        
        # Address Information
        address_group = QGroupBox("Address Information")
        address_form = QFormLayout()
        address_form.setSpacing(10)
        address_form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        
        self.street_edit = QLineEdit(self.user_data.get('streetAddress', ''))
        self.city_edit = QLineEdit(self.user_data.get('l', ''))
        self.state_edit = QLineEdit(self.user_data.get('st', ''))
        self.postal_edit = QLineEdit(self.user_data.get('postalCode', ''))
        
        # Country dropdown
        self.country_combo = QComboBox()
        countries = [
            ("United States", "US", "840"),
            ("Canada", "CA", "124"),
            ("United Kingdom", "GB", "826")
        ]
        
        for country_name, country_code, country_num in countries:
            self.country_combo.addItem(country_name, (country_code, country_num))
            
        # Set current country
        current_country = self.user_data.get('c', '')
        if current_country:
            for i in range(self.country_combo.count()):
                if self.country_combo.itemData(i)[0] == current_country:
                    self.country_combo.setCurrentIndex(i)
                    break
        
        address_form.addRow("Street Address:", self.street_edit)
        address_form.addRow("City:", self.city_edit)
        address_form.addRow("State/Province:", self.state_edit)
        address_form.addRow("Postal Code:", self.postal_edit)
        address_form.addRow("Country:", self.country_combo)
        
        address_group.setLayout(address_form)
        job_layout.addWidget(address_group)
        
        # Setup specialized tabs
        self.attributes_tab = AttributesTab(self, self.ldap_conn, self.base_dn)
        self.attributes_tab.set_attributes(self.user_data)
        
        self.groups_tab = GroupsTab(self, self.ldap_conn, self.base_dn)
        self.groups_tab.set_edit_mode(True, self.user_data.get('memberOf', []))
        
        # Add all tabs
        tab_widget.addTab(general_tab, "General")
        tab_widget.addTab(job_tab, "Job & Address")
        tab_widget.addTab(self.groups_tab, "Group Membership")
        tab_widget.addTab(self.attributes_tab, "Attributes")
        
        main_layout.addWidget(tab_widget)
        
        # Buttons
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        self.cancel_button = QPushButton("Cancel")
        self.cancel_button.setObjectName("secondaryButton")
        self.cancel_button.clicked.connect(self.close)
        button_layout.addWidget(self.cancel_button)
        
        self.save_button = QPushButton("Save Changes")
        self.save_button.clicked.connect(self.save_changes)
        button_layout.addWidget(self.save_button)
        
        main_layout.addLayout(button_layout)
        
        # Status label
        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(self.status_label)
        
        self.setLayout(main_layout)
        
        # Connect signals for tracking changes
        self.connect_change_signals()
    
    # Event handling methods
    def update_contractor_status(self):
        """Update SAM account name when contractor status changes"""
        if self.sam_account_edit.text().strip():
            self.auto_update_fields()
            
    def auto_update_fields(self):
        """Auto-update display name and SAM account based on name"""
        first = self.first_name_edit.text().strip()
        last = self.last_name_edit.text().strip()
        
        # Update display name
        self.display_name_edit.setText(f"{first} {last}".strip())
        
        # Auto-generate SAM account in create mode
        if (first and last and not self.sam_account_edit.hasFocus() and 
                self.mode == UserOperation.CREATE):
            self.status_label.setText("Generating username...")
            QApplication.processEvents()
            
            candidate = auto_generate_sam_account(first, last, self.ldap_conn)
            if candidate:
                # Add contractor suffix if needed
                if hasattr(self, 'contractor_chk') and self.contractor_chk.isChecked():
                    if len(candidate) > 17:  # Leave room for suffix
                        candidate = candidate[:17]
                    candidate += "-c"
                
                self.sam_account_edit.setText(candidate)
                self.status_label.setText(f"Suggested username: {candidate}")
            else:
                self.status_label.setText("Could not generate a unique username")
                
        self.sync_upn_field()
        
    def sync_upn_field(self):
        """Sync UPN prefix with SAM account"""
        self.upn_edit.setText(self.sam_account_edit.text().strip())
    
    def connect_change_signals(self):
        """Connect signals to track field changes in edit mode"""
        # Map fields to attributes
        field_to_attr = {
            self.first_name_edit: 'givenName',
            self.last_name_edit: 'sn',
            self.display_name_edit: 'displayName',
            self.email_edit: 'mail',
            self.phone_edit: 'telephoneNumber',
            self.mobile_edit: 'mobile',
            self.upn_edit: 'userPrincipalName',
            self.job_title_edit: 'title',
            self.department_edit: 'department',
            self.company_edit: 'company',
            self.description_edit: 'description',
            self.street_edit: 'streetAddress',
            self.city_edit: 'l',
            self.state_edit: 'st',
            self.postal_edit: 'postalCode'
        }
        
        # Connect text fields
        for field, attr in field_to_attr.items():
            field.textChanged.connect(lambda _, a=attr: self.mark_as_modified(a))
        
        # Connect checkboxes and comboboxes
        self.upn_suffix_combo.currentIndexChanged.connect(
            lambda: self.mark_as_modified('userPrincipalName'))
        self.disabled_chk.stateChanged.connect(
            lambda: self.mark_as_modified('userAccountControl'))
        self.pwd_never_expires_chk.stateChanged.connect(
            lambda: self.mark_as_modified('userAccountControl'))
        self.cannot_change_pwd_chk.stateChanged.connect(
            lambda: self.mark_as_modified('userAccountControl'))
        self.pwd_expired_chk.stateChanged.connect(
            lambda: self.mark_as_modified('pwdLastSet'))
        self.country_combo.currentIndexChanged.connect(
            lambda: self.mark_as_modified('country'))
    
    def mark_as_modified(self, attribute):
        """Mark an attribute as modified in edit mode"""
        self.modified_attributes[attribute] = True
    
    # Template management
    def update_template_list(self):
        """Update the template dropdown with available templates"""
        self.template_combo.clear()
        self.template_combo.addItem("-- Select Template --", None)
        for name in self.template_manager.get_template_names():
            self.template_combo.addItem(name, name)
            
    def save_current_as_template(self):
        """Save current form values as a new template"""
        name, ok = QInputDialog.getText(self, "Save Template", "Template Name:")
        if ok and name:
            # Collect current settings
            settings = {
                "company": self.company_edit.text(),
                "department": self.department_edit.text(),
                "jobTitle": self.job_title_edit.text(),
                "ou": self.ou_combo.currentData() if hasattr(self, 'ou_combo') else None,
                "street": self.street_edit.text(),
                "city": self.city_edit.text(),
                "state": self.state_edit.text(),
                "postalCode": self.postal_edit.text(),
                "country": self.country_combo.currentData(),
                "passwordOptions": {
                    "mustChange": self.change_password_chk.isChecked() if hasattr(self, 'change_password_chk') else False,
                    "neverExpires": self.never_expires_chk.isChecked() if hasattr(self, 'never_expires_chk') else False
                },
                "selectedGroups": self.groups_tab.get_selected_groups(),
                "isContractor": self.contractor_chk.isChecked() if hasattr(self, 'contractor_chk') else False,
                "customAttributes": self.attributes_tab.get_attributes()
            }
            
            template = UserTemplate(name, settings)
            self.template_manager.add_template(template)
            self.update_template_list()
            
            # Select the new template
            index = self.template_combo.findText(name)
            if index >= 0:
                self.template_combo.setCurrentIndex(index)
                
            QMessageBox.information(self, "Template Saved", 
                                  f"Template '{name}' saved successfully")
            
    def load_template(self):
        """Load selected template into the form"""
        template_name = self.template_combo.currentData()
        if not template_name:
            return
            
        template = self.template_manager.get_template(template_name)
        if not template:
            return
            
        # Preview the template
        preview = QDialog(self)
        preview.setWindowTitle(f"Preview Template: {template.name}")
        preview.setMinimumWidth(500)
        preview.setMinimumHeight(400)
        
        layout = QVBoxLayout()
        preview_text = QTextEdit()
        preview_text.setReadOnly(True)
        
        # Format template data for preview
        preview_html = f"<h3>Template: {template.name}</h3>"
        preview_html += "<table border='0' cellspacing='5' cellpadding='5'>"
        
        for key, value in template.settings.items():
            if key == "passwordOptions":
                options_list = []
                pw_options = value
                if pw_options.get("mustChange", False):
                    options_list.append("User must change password at next logon")
                if pw_options.get("neverExpires", False):
                    options_list.append("Password never expires")
                preview_html += f"<tr><td><b>Password Options:</b></td><td>{', '.join(options_list)}</td></tr>"
            elif key == "selectedGroups" and value:
                preview_html += f"<tr><td><b>Groups:</b></td><td>{', '.join(value)}</td></tr>"
            elif key == "country" and value is not None:
                country_code, country_num = value
                country_name = "Unknown"
                for i in range(self.country_combo.count()):
                    if self.country_combo.itemData(i) == value:
                        country_name = self.country_combo.itemText(i)
                        break
                preview_html += f"<tr><td><b>Country:</b></td><td>{country_name} ({country_code})</td></tr>"
            elif key == "isContractor":
                preview_html += f"<tr><td><b>Contractor:</b></td><td>{'Yes' if value else 'No'}</td></tr>"
            elif key == "customAttributes" and value:
                attr_list = [f"{attr}: {val}" for attr, val in value.items()]
                preview_html += f"<tr><td><b>Custom Attributes:</b></td><td>{', '.join(attr_list)}</td></tr>"
            else:
                preview_html += f"<tr><td><b>{key}:</b></td><td>{value}</td></tr>"
        
        preview_html += "</table>"
        preview_text.setHtml(preview_html)
        layout.addWidget(preview_text)
        
        # Buttons
        button_layout = QHBoxLayout()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.clicked.connect(preview.reject)
        
        apply_btn = QPushButton("Apply Template")
        apply_btn.clicked.connect(preview.accept)
        
        button_layout.addWidget(cancel_btn)
        button_layout.addWidget(apply_btn)
        layout.addLayout(button_layout)
        
        preview.setLayout(layout)
        
        # Apply if accepted
        if preview.exec() == QDialog.DialogCode.Accepted:
            self._apply_template(template)
            
    def _apply_template(self, template):
        """Apply the template to the form"""
        settings = template.settings
        
        # Apply settings to form fields
        field_mappings = {
            "company": self.company_edit,
            "department": self.department_edit,
            "jobTitle": self.job_title_edit,
            "street": self.street_edit,
            "city": self.city_edit,
            "state": self.state_edit,
            "postalCode": self.postal_edit
        }
        
        # Set text fields
        for key, field in field_mappings.items():
            if key in settings:
                field.setText(settings[key])
        
        # Set OU if it exists in our list and we have an OU combo
        if "ou" in settings and hasattr(self, 'ou_combo'):
            for i in range(self.ou_combo.count()):
                if self.ou_combo.itemData(i) == settings["ou"]:
                    self.ou_combo.setCurrentIndex(i)
                    break
        
        # Set country
        if "country" in settings:
            for i in range(self.country_combo.count()):
                if self.country_combo.itemData(i) == settings["country"]:
                    self.country_combo.setCurrentIndex(i)
                    break
        
        # Password options - applicable to create mode
        if "passwordOptions" in settings:
            pw_options = settings["passwordOptions"]
            if hasattr(self, 'change_password_chk') and "mustChange" in pw_options:
                self.change_password_chk.setChecked(pw_options["mustChange"])
            if hasattr(self, 'never_expires_chk') and "neverExpires" in pw_options:
                self.never_expires_chk.setChecked(pw_options["neverExpires"])
        
        # Contractor status - applicable to create mode
        if "isContractor" in settings and hasattr(self, 'contractor_chk'):
            self.contractor_chk.setChecked(settings["isContractor"])
        
        # Groups
        if "selectedGroups" in settings and settings["selectedGroups"]:
            self.groups_tab.set_selected_groups(settings["selectedGroups"])
        
        # Custom attributes
        if "customAttributes" in settings and settings["customAttributes"]:
            self.attributes_tab.set_attributes(settings["customAttributes"])
        
        QMessageBox.information(self, "Template Applied", 
                             f"Template '{template.name}' applied successfully")
    
    def manage_templates(self):
        """Open a dialog to manage templates"""
        dialog = QDialog(self)
        dialog.setWindowTitle("Manage Templates")
        dialog.setMinimumWidth(400)
        dialog.setMinimumHeight(300)
        
        layout = QVBoxLayout()
        
        # Template list
        list_label = QLabel("Available Templates:")
        layout.addWidget(list_label)
        
        template_list = QListWidget()
        template_list.addItems(self.template_manager.get_template_names())
        layout.addWidget(template_list)
        
        # Buttons for managing templates
        button_layout = QHBoxLayout()
        
        delete_btn = QPushButton("Delete")
        delete_btn.clicked.connect(lambda: self.delete_template(template_list))
        button_layout.addWidget(delete_btn)
        
        export_btn = QPushButton("Export All")
        export_btn.clicked.connect(self.export_templates)
        button_layout.addWidget(export_btn)
        
        import_btn = QPushButton("Import")
        import_btn.clicked.connect(lambda: self.import_templates(template_list))
        button_layout.addWidget(import_btn)
        
        layout.addLayout(button_layout)
        
        # Close button
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(dialog.accept)
        layout.addWidget(close_btn)
        
        dialog.setLayout(layout)
        dialog.exec()
        
    def delete_template(self, template_list):
        """Delete the selected template"""
        selected_items = template_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a template to delete")
            return
            
        template_name = selected_items[0].text()
        
        reply = QMessageBox.question(
            self, 
            "Confirm Deletion", 
            f"Delete template '{template_name}'?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            success = self.template_manager.delete_template(template_name)
            if success:
                QMessageBox.information(self, "Template Deleted", 
                                      f"Template '{template_name}' deleted successfully")
                # Update the list
                template_list.clear()
                template_list.addItems(self.template_manager.get_template_names())
                
                # Update the dropdown
                self.update_template_list()
            else:
                QMessageBox.warning(self, "Deletion Failed", 
                                   f"Failed to delete template '{template_name}'")
                                   
    def export_templates(self):
        """Export all templates to a file"""
        file_path, _ = QFileDialog.getSaveFileName(
            self, "Export Templates", "", "JSON Files (*.json)"
        )
        
        if file_path:
            try:
                self.template_manager.export_templates(file_path)
                QMessageBox.information(self, "Templates Exported", 
                                      f"Templates exported to {file_path}")
            except Exception as e:
                QMessageBox.critical(self, "Export Failed", 
                                   f"Failed to export templates: {str(e)}")
                                   
    def import_templates(self, template_list):
        """Import templates from a file"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Import Templates", "", "JSON Files (*.json)"
        )
        
        if file_path:
            try:
                count = self.template_manager.import_templates(file_path)
                QMessageBox.information(self, "Templates Imported", 
                                      f"{count} templates imported successfully")
                                      
                # Update the list
                template_list.clear()
                template_list.addItems(self.template_manager.get_template_names())
                
                # Update the dropdown
                self.update_template_list()
            except Exception as e:
                QMessageBox.critical(self, "Import Failed", 
                                   f"Failed to import templates: {str(e)}")

    def create_user(self):
        """Create a new user in Active Directory"""
        self.status_label.setText("Creating user...")
        QApplication.processEvents()
        
        first = self.first_name_edit.text().strip()
        last = self.last_name_edit.text().strip()
        display_name = self.display_name_edit.text().strip()
        sam_account = self.sam_account_edit.text().strip()
        upn_suffix = self.upn_suffix_combo.currentText().strip()
        upn = f"{self.upn_edit.text()}{upn_suffix}"
        password = self.password_edit.text()
        confirm_password = self.confirm_password_edit.text()
        ou_dn = self.ou_combo.currentData()

        if not all([first, last, password, confirm_password]):
            QMessageBox.warning(self, "Input Error", "Please fill in all required fields (First Name, Last Name, Password).")
            self.status_label.setText("Error: Missing required fields")
            return
            
        if password != confirm_password:
            QMessageBox.warning(self, "Input Error", "Passwords do not match.")
            self.status_label.setText("Error: Passwords do not match")
            return

        if not display_name:
            display_name = f"{first} {last}"
            self.display_name_edit.setText(display_name)

        if not sam_account:
            candidate = auto_generate_sam_account(first, last, self.ldap_conn)
            if candidate is None:
                reply = QMessageBox.question(
                    self, "SAM Account Name",
                    "Automated username is too long or already in use. Would you like to manually set it?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                )
                if reply == QMessageBox.StandardButton.Yes:
                    self.status_label.setText("Please enter a SAM account name manually")
                    return
                else:
                    self.status_label.setText("Operation cancelled")
                    return
            else:
                # Add contractor suffix if contractor checkbox is checked
                if self.contractor_chk.isChecked():
                    # Check if adding "-c" would exceed the 20 character limit
                    if len(candidate) > 17:  # Leave room for "-c"
                        candidate = candidate[:17]
                    candidate += "-c"
                
                sam_account = candidate
                self.sam_account_edit.setText(sam_account)
                self.upn_edit.setText(sam_account)

        new_user_dn = f"CN={display_name},{ou_dn}"
        
        # Create a new connection using the same DC but port 636
        dc_host = self.ldap_conn.server.host
        bind_user = self.ldap_conn.user
        bind_pass = self.ldap_conn.password

        try:
            # Create server with SSL
            server = Server(dc_host, port=636, use_ssl=True)
            
            # Create connection with the server
            write_conn = Connection(
                server,
                user=bind_user,
                password=bind_pass,
                authentication='SIMPLE',
                auto_bind=True
            )
            
            # Base attributes with password never expires by default (66048 = 512 | 0x10000)
            attributes = {
                "objectClass": ["top", "person", "organizationalPerson", "user"],
                "cn": display_name,
                "sn": last,
                "givenName": first,
                "displayName": display_name,
                "sAMAccountName": sam_account,
                "userPrincipalName": upn,
                "mail": upn,  # Set email to match UPN
                "userAccountControl": 66048,  # Password never expires by default
                "unicodePwd": encode_password(password)
            }
            
            # Add job title and department if they're filled in
            job_title = self.job_title_edit.text().strip()
            if job_title:
                attributes["title"] = job_title

            department = self.department_edit.text().strip()
            if department:
                attributes["department"] = department
                
            # Add company if filled in
            company = self.company_edit.text().strip()
            if company:
                attributes["company"] = company

            # Add address information if filled in
            street = self.street_edit.text().strip()
            if street:
                attributes["streetAddress"] = street
                
            city = self.city_edit.text().strip()
            if city:
                attributes["l"] = city
                
            state = self.state_edit.text().strip()
            if state:
                attributes["st"] = state
                
            postal = self.postal_edit.text().strip()
            if postal:
                attributes["postalCode"] = postal

            # Set country based on selection
            country_idx = self.country_combo.currentIndex()
            if country_idx >= 0:
                country_code, country_num = self.country_combo.itemData(country_idx)
                country_name = self.country_combo.currentText()
                
                attributes["c"] = country_code
                attributes["co"] = country_name
                attributes["countryCode"] = country_num
                
            # Add custom attributes from attributes tab
            custom_attributes = self.attributes_tab.get_attributes()
            for attr_name, value in custom_attributes.items():
                # Skip attributes that are already set
                if attr_name in attributes:
                    continue
                    
                attributes[attr_name] = value if isinstance(value, list) else [value]

            self.status_label.setText(f"Creating user: {display_name}...")
            QApplication.processEvents()
            
            result = write_conn.add(new_user_dn, attributes=attributes)
            
            if not result:
                error_desc = write_conn.result.get('description', 'Unknown error')
                error_msg = write_conn.result.get('message', '')
                write_conn.unbind()
                QMessageBox.critical(self, "Error", f"Failed to create user:\nDescription: {error_desc}\nMessage: {error_msg}")
                self.status_label.setText("Error creating user")
                return

            # Set pwdLastSet if needed
            if self.change_password_chk.isChecked():
                pwd_last_set = {
                    "pwdLastSet": [(MODIFY_REPLACE, [0])]
                }
                write_conn.modify(new_user_dn, pwd_last_set)
                
            # Add user to selected groups
            selected_groups = self.groups_tab.get_selected_groups()
            for group_name in selected_groups:
                # Look up the group's DN
                found_group = False
                for group_info in self.groups_tab.all_groups:
                    if group_info["name"] == group_name:
                        group_dn = group_info["dn"]
                        found_group = True
                        break
                        
                if found_group:
                    try:
                        # Add the user to the group
                        write_conn.modify(
                            group_dn,
                            {'member': [(MODIFY_ADD, [new_user_dn])]}
                        )
                    except Exception as e:
                        QMessageBox.warning(
                            self, 
                            "Group Error", 
                            f"Failed to add user to group {group_name}: {e}"
                        )

            write_conn.unbind()
            self.status_label.setText("User created successfully")
            self.user_action_completed.emit()  # Emit signal to refresh the directory browser
            QTimer.singleShot(1000, self.close)  # Close after delay

        except LDAPException as e:
            QMessageBox.critical(self, "LDAP Error", f"Exception: {e}")
            self.status_label.setText("LDAP error occurred")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Unexpected error: {e}")
            self.status_label.setText("An unexpected error occurred")
            
    def save_changes(self):
        """Save changes to an existing user"""
        self.status_label.setText("Saving changes...")
        QApplication.processEvents()
        
        # Prepare modifications
        modifications = {}
        
        # Personal info
        if 'givenName' in self.modified_attributes:
            modifications['givenName'] = [(MODIFY_REPLACE, [self.first_name_edit.text()])]
            
        if 'sn' in self.modified_attributes:
            modifications['sn'] = [(MODIFY_REPLACE, [self.last_name_edit.text()])]
            
        if 'displayName' in self.modified_attributes:
            modifications['displayName'] = [(MODIFY_REPLACE, [self.display_name_edit.text()])]
            
        if 'mail' in self.modified_attributes:
            modifications['mail'] = [(MODIFY_REPLACE, [self.email_edit.text()])]
            
        if 'telephoneNumber' in self.modified_attributes:
            modifications['telephoneNumber'] = [(MODIFY_REPLACE, [self.phone_edit.text()])]
            
        if 'mobile' in self.modified_attributes:
            modifications['mobile'] = [(MODIFY_REPLACE, [self.mobile_edit.text()])]
        
        # Account info
        if 'userPrincipalName' in self.modified_attributes:
            upn_prefix = self.upn_edit.text()
            upn_suffix = self.upn_suffix_combo.currentText()
            upn = f"{upn_prefix}{upn_suffix}"
            modifications['userPrincipalName'] = [(MODIFY_REPLACE, [upn])]
        
        # UAC flags
        if 'userAccountControl' in self.modified_attributes:
            # Get original UAC
            uac = self.user_data.get('userAccountControl', 0)
            
            # Update flags based on checkboxes
            if self.disabled_chk.isChecked():
                uac |= 2  # ADS_UF_ACCOUNTDISABLE
            else:
                uac &= ~2
                
            if self.pwd_never_expires_chk.isChecked():
                uac |= 65536  # ADS_UF_DONT_EXPIRE_PASSWD
            else:
                uac &= ~65536
                
            if self.cannot_change_pwd_chk.isChecked():
                uac |= 64  # ADS_UF_PASSWD_CANT_CHANGE
            else:
                uac &= ~64
                
            modifications['userAccountControl'] = [(MODIFY_REPLACE, [uac])]
        
        # Password must change at next logon
        if 'pwdLastSet' in self.modified_attributes:
            if self.pwd_expired_chk.isChecked():
                modifications['pwdLastSet'] = [(MODIFY_REPLACE, [0])]
            else:
                modifications['pwdLastSet'] = [(MODIFY_REPLACE, [-1])]
        
        # Reset password if requested
        if self.new_password_edit.text() and self.new_password_edit.text() == self.confirm_password_edit.text():
            modifications['unicodePwd'] = [(MODIFY_REPLACE, [encode_password(self.new_password_edit.text())])]
        elif self.new_password_edit.text():
            QMessageBox.warning(self, "Password Mismatch", "The passwords you entered do not match.")
            self.status_label.setText("Password mismatch")
            return
        
        # Job info
        if 'title' in self.modified_attributes:
            modifications['title'] = [(MODIFY_REPLACE, [self.job_title_edit.text()])]
            
        if 'department' in self.modified_attributes:
            modifications['department'] = [(MODIFY_REPLACE, [self.department_edit.text()])]
            
        if 'company' in self.modified_attributes:
            modifications['company'] = [(MODIFY_REPLACE, [self.company_edit.text()])]
            
        if 'description' in self.modified_attributes:
            modifications['description'] = [(MODIFY_REPLACE, [self.description_edit.text()])]
        
        # Address info
        if 'streetAddress' in self.modified_attributes:
            modifications['streetAddress'] = [(MODIFY_REPLACE, [self.street_edit.text()])]
            
        if 'l' in self.modified_attributes:
            modifications['l'] = [(MODIFY_REPLACE, [self.city_edit.text()])]
            
        if 'st' in self.modified_attributes:
            modifications['st'] = [(MODIFY_REPLACE, [self.state_edit.text()])]
            
        if 'postalCode' in self.modified_attributes:
            modifications['postalCode'] = [(MODIFY_REPLACE, [self.postal_edit.text()])]
            
        if 'country' in self.modified_attributes:
            country_idx = self.country_combo.currentIndex()
            if country_idx >= 0:
                country_code, country_num = self.country_combo.itemData(country_idx)
                country_name = self.country_combo.currentText()
                
                modifications['c'] = [(MODIFY_REPLACE, [country_code])]
                modifications['co'] = [(MODIFY_REPLACE, [country_name])]
                modifications['countryCode'] = [(MODIFY_REPLACE, [country_num])]
        
        # Get any custom attributes from the attributes tab
        custom_attributes = self.attributes_tab.get_attributes()
        for attr_name, value in custom_attributes.items():
            # Skip attributes that are handled elsewhere
            if attr_name in modifications or attr_name in [
                'givenName', 'sn', 'displayName', 'mail', 'telephoneNumber', 'mobile',
                'userPrincipalName', 'userAccountControl', 'pwdLastSet', 'unicodePwd',
                'title', 'department', 'company', 'description', 'streetAddress',
                'l', 'st', 'postalCode', 'c', 'co', 'countryCode'
            ]:
                continue
                
            # Compare with original values to see if modified
            original_value = self.user_data.get(attr_name, "")
            if value != original_value:
                modifications[attr_name] = [(MODIFY_REPLACE, value if isinstance(value, list) else [value])]
        
        # Now apply all the modifications to the user object
        if modifications:
            try:
                result = self.ldap_conn.modify(self.user_dn, modifications)
                if result:
                    self.status_label.setText("Changes saved successfully")
                    self.user_action_completed.emit()
                    QTimer.singleShot(1000, self.close)
                else:
                    error_msg = self.ldap_conn.result.get('message', 'Unknown error')
                    QMessageBox.critical(self, "Save Failed", f"Failed to save changes: {error_msg}")
                    self.status_label.setText("Save failed")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save changes: {e}")
                self.status_label.setText("Error saving changes")
        else:
            self.status_label.setText("No changes to save")
