import sys
import ssl
import os

# Add the current directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QComboBox,
    QVBoxLayout, QHBoxLayout, QMessageBox, QGroupBox, QCheckBox
)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QFont
from ldap3 import Server, Connection, ALL, Tls, SUBTREE
from ldap3.core.exceptions import LDAPException

# Import will be used when running as part of the application
try:
    from helpers import domain_to_base_dn, get_app_stylesheet
except ImportError:
    # Define these here for standalone testing
    def domain_to_base_dn(domain: str) -> str:
        """
        Convert a full DNS domain (e.g., 'corp.adenshomelab.xyz') into a base DN.
        E.g., 'corp.adenshomelab.xyz' -> 'DC=corp,DC=adenshomelab,DC=xyz'
        """
        parts = domain.split('.')
        return ','.join(f"DC={part}" for part in parts)
    
    def get_app_stylesheet():
        """Returns the application's stylesheet for a modern look"""
        return """
        QWidget {
            font-family: 'Segoe UI', Arial, sans-serif;
            font-size: 10pt;
        }
        /* ... stylesheet content ... */
        """

# ========================================================
# DOMAIN CONFIGURATION - UPDATE THIS SECTION AS NEEDED
# ========================================================

# Define your domains here - this is the only place you need to modify
# Format: {NetBIOS_NAME: (FQDN, [List of Domain Controllers])}
DOMAIN_CONFIG = {
    "CORP": ("corp.adenshomelab.xyz", [
        "SDMSRVDCP001.corp.adenshomelab.xyz",
        # Add more DCs as needed
    ]),
    "SDNM": ("sdnm.adenshomelab.xyz", [
        "SDNMSRVDCP001.sdnm.adenshomelab.xyz",
        # Add more DCs as needed
    ]),
    # Add more domains as needed using the same format:
    # "NETBIOS": ("domain.fqdn", ["dc1.domain.fqdn", "dc2.domain.fqdn"]),
}

# Default domain to select in the UI
DEFAULT_DOMAIN = "CORP"

# ========================================================


class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AD Management Tool")
        self.setMinimumWidth(500)
        self.setMinimumHeight(450)
        self.setup_ui()

    def setup_ui(self):
        main_layout = QVBoxLayout()
        main_layout.setSpacing(20)
        main_layout.setContentsMargins(30, 30, 30, 30)
        
        # Add a logo or title at the top
        logo_label = QLabel("Active Directory Management")
        logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        logo_font = QFont()
        logo_font.setPointSize(16)
        logo_font.setBold(True)
        logo_label.setFont(logo_font)
        main_layout.addWidget(logo_label)
        
        # Subtitle
        subtitle = QLabel("Login with your domain credentials")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle_font = QFont()
        subtitle_font.setPointSize(10)
        subtitle.setFont(subtitle_font)
        main_layout.addWidget(subtitle)
        
        # Add some spacing
        main_layout.addSpacing(20)
        
        # Login form in a group box
        login_group = QGroupBox("Authentication")
        login_layout = QVBoxLayout()
        login_layout.setSpacing(15)
        
        # Username row with domain dropdown
        username_layout = QHBoxLayout()
        username_layout.setSpacing(10)
        user_label = QLabel("Username:")
        user_label.setMinimumWidth(80)
        username_layout.addWidget(user_label)
        
        # Domain prefix dropdown (NetBIOS) for username
        self.domain_combo = QComboBox()
        for netbios in DOMAIN_CONFIG.keys():
            self.domain_combo.addItem(netbios, netbios)
        
        # Set the default domain
        default_index = self.domain_combo.findData(DEFAULT_DOMAIN)
        if default_index >= 0:
            self.domain_combo.setCurrentIndex(default_index)
        
        self.domain_combo.setFixedWidth(100)
        username_layout.addWidget(self.domain_combo)
        
        # Separator label
        separator_label = QLabel("\\")
        separator_label.setFixedWidth(15)
        separator_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        username_layout.addWidget(separator_label)
        
        # Username field
        self.user_edit = QLineEdit()
        self.user_edit.setPlaceholderText("username")
        username_layout.addWidget(self.user_edit)
        login_layout.addLayout(username_layout)
        
        # Password row
        pass_layout = QHBoxLayout()
        pass_layout.setSpacing(10)
        pass_label = QLabel("Password:")
        pass_label.setMinimumWidth(80)
        pass_layout.addWidget(pass_label)
        
        self.pass_edit = QLineEdit()
        self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_edit.setPlaceholderText("Enter password")
        pass_layout.addWidget(self.pass_edit)
        login_layout.addLayout(pass_layout)
        
        # Domain Controller selection - showing all domain controllers regardless of selected domain
        dc_layout = QHBoxLayout()
        dc_layout.setSpacing(10)
        dc_label = QLabel("Domain Controller:")
        dc_label.setMinimumWidth(80)
        dc_layout.addWidget(dc_label)
        
        self.dc_combo = QComboBox()
        # Populate with all domain controllers from all domains
        for netbios, (fqdn, dc_list) in DOMAIN_CONFIG.items():
            for dc in dc_list:
                # Add domain info to the display text to show which domain each DC belongs to
                self.dc_combo.addItem(f"{dc} ({netbios})", dc)
            
        # Select first item
        if self.dc_combo.count() > 0:
            self.dc_combo.setCurrentIndex(0)
            
        dc_layout.addWidget(self.dc_combo)
        login_layout.addLayout(dc_layout)
        
        # Advanced options
        advanced_layout = QVBoxLayout()
        self.advanced_chk = QCheckBox("Advanced Options")
        self.advanced_chk.stateChanged.connect(self.toggle_advanced_options)
        advanced_layout.addWidget(self.advanced_chk)
        
        # Custom server input (hidden by default)
        self.custom_server_layout = QHBoxLayout()
        custom_server_label = QLabel("Custom DC:")
        custom_server_label.setMinimumWidth(80)
        self.custom_server_layout.addWidget(custom_server_label)
        
        self.custom_server_edit = QLineEdit()
        self.custom_server_edit.setPlaceholderText("Enter custom DC hostname")
        self.custom_server_layout.addWidget(self.custom_server_edit)
        advanced_layout.addLayout(self.custom_server_layout)
        
        # Add advanced options to login layout
        login_layout.addLayout(advanced_layout)
        
        # Hide advanced options by default
        self.custom_server_layout.setEnabled(False)
        
        login_group.setLayout(login_layout)
        main_layout.addWidget(login_group)
        
        # Login button with improved styling
        button_layout = QHBoxLayout()
        button_layout.addStretch()
        
        self.login_button = QPushButton("Login")
        self.login_button.setMinimumWidth(120)
        self.login_button.setMinimumHeight(40)
        self.login_button.clicked.connect(self.login)
        button_layout.addWidget(self.login_button)
        
        button_layout.addStretch()
        main_layout.addLayout(button_layout)
        
        # Status indicator at the bottom
        self.status_label = QLabel("Ready to connect")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(self.status_label)
        
        main_layout.addStretch()
        
        self.setLayout(main_layout)
        
        # Setup keyboard shortcuts
        self.user_edit.returnPressed.connect(lambda: self.pass_edit.setFocus())
        self.pass_edit.returnPressed.connect(self.login)
    
    def toggle_advanced_options(self, state):
        """Toggle visibility of advanced options"""
        is_checked = state == Qt.CheckState.Checked
        self.custom_server_layout.setEnabled(is_checked)

    def login(self):
        """Authenticate and log in to the selected domain"""
        self.status_label.setText("Connecting...")
        QApplication.processEvents()
        
        # Get selected domain NetBIOS name
        domain_idx = self.domain_combo.currentIndex()
        if domain_idx < 0:
            QMessageBox.warning(self, "Input Error", "No domain selected.")
            self.status_label.setText("Login failed")
            return
            
        domain_netbios = self.domain_combo.itemData(domain_idx)
        
        # Get domain FQDN from config
        if domain_netbios not in DOMAIN_CONFIG:
            QMessageBox.warning(self, "Input Error", "Selected domain not configured.")
            self.status_label.setText("Login failed")
            return
            
        domain_fqdn, _ = DOMAIN_CONFIG[domain_netbios]
        
        username = self.user_edit.text().strip()
        password = self.pass_edit.text().strip()
        
        # Check if the username includes a domain prefix
        if '\\' in username:
            # Remove the domain prefix if present
            username = username.split('\\', 1)[1]
        
        # Format as DOMAIN\username for display
        display_username = f"{domain_netbios}\\{username}"
        
        # Check if we should use a custom server
        if self.advanced_chk.isChecked() and self.custom_server_edit.text().strip():
            dc_fqdn = self.custom_server_edit.text().strip()
        else:
            # Get selected DC
            dc_idx = self.dc_combo.currentIndex()
            if dc_idx < 0:
                QMessageBox.warning(self, "Input Error", "No domain controller selected.")
                self.status_label.setText("Login failed")
                return
                
            dc_fqdn = self.dc_combo.itemData(dc_idx)  # DC FQDN

        if not username or not password:
            QMessageBox.warning(self, "Input Error", "Please enter both username and password.")
            self.status_label.setText("Authentication failed")
            return

        # Use UPN format for binding
        bind_user = f"{username}@{domain_fqdn}"

        # Cross-domain authentication usually requires Global Catalog
        # Determine if we're doing cross-domain authentication
        dc_domain = ""
        for netbios, (fqdn, dc_list) in DOMAIN_CONFIG.items():
            if dc_fqdn in dc_list:
                dc_domain = fqdn
                break
                
        # If DC belongs to a different domain than the user, use Global Catalog port
        if dc_domain and dc_domain.lower() != domain_fqdn.lower():
            port = 3269  # Global Catalog port
        else:
            port = 636   # Regular LDAP port

        tls_config = Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLSv1_2)

        try:
            server = Server(f"ldaps://{dc_fqdn}", port=port, tls=tls_config, get_info=ALL)
        except Exception as e:
            QMessageBox.critical(self, "Server Error", f"Failed to create LDAP server object:\n{e}")
            self.status_label.setText("Connection error")
            return

        try:
            conn = Connection(server, user=bind_user, password=password, auto_bind=True)
        except LDAPException as e:
            QMessageBox.critical(self, "Authentication Failed", f"Failed to bind to AD:\n{e}")
            self.status_label.setText("Authentication failed")
            return

        # Determine base DN for searching
        try:
            base_dn_for_admin = server.info.naming_contexts[0]
        except Exception:
            base_dn_for_admin = domain_to_base_dn(domain_fqdn)

        # Check if user exists and get groups
        search_filter = f"(sAMAccountName={username})"
        try:
            # For cross-domain searches, we might need to specify the domain in the search
            if port == 3269:  # Global Catalog
                # Empty base for Global Catalog searches
                search_base = ""
            else:
                search_base = base_dn_for_admin
                
            conn.search(search_base=search_base, search_filter=search_filter, attributes=['memberOf'])
        except LDAPException as e:
            QMessageBox.critical(self, "Search Error", f"LDAP search failed:\n{e}")
            conn.unbind()
            self.status_label.setText("Search error")
            return

        if not conn.entries:
            QMessageBox.critical(self, "User Not Found", "User not found in Active Directory.")
            conn.unbind()
            self.status_label.setText("User not found")
            return

        # Check if user is in admin groups
        entry = conn.entries[0]
        groups = entry.memberOf.values if 'memberOf' in entry else []
        is_admin = any("CN=Domain Admins" in g or "CN=Enterprise Admins" in g for g in groups)
        conn.unbind()

        if is_admin:
            self.status_label.setText(f"Authentication successful for {display_username}")
            QTimer.singleShot(500, lambda: self.open_browser_window(
                domain_netbios, domain_fqdn, username, password, 
                dc_fqdn, base_dn_for_admin, port))
        else:
            QMessageBox.critical(self, "Authorization Failed", 
                                f"User {display_username} is not a member of Domain Admins or Enterprise Admins.")
            self.status_label.setText("Authorization failed")
            
    def open_browser_window(self, login_domain, login_domain_dns, username, password, dc_fqdn, ou_base_dn, port):
        # Import DirectoryBrowser here to avoid circular imports
        from DirectoryBrowser import DirectoryBrowser
        
        self.browser = DirectoryBrowser(login_domain, login_domain_dns, username, password, dc_fqdn, ou_base_dn, port)
        self.browser.show()
        self.close()


# Allow running this file directly for testing
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(get_app_stylesheet())
    login = LoginWindow()
    login.show()
    sys.exit(app.exec())