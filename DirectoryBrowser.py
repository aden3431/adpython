import sys
import ssl
import os

# Add the current directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QComboBox,
    QVBoxLayout, QHBoxLayout, QMessageBox, QTreeWidget, QTreeWidgetItem,
    QTableWidget, QTableWidgetItem, QSplitter, QMainWindow, QStatusBar,
    QTabWidget, QToolBar, QSizePolicy, QHeaderView
)
from PyQt6.QtCore import Qt, QSize, QTimer, pyqtSignal
from PyQt6.QtGui import QIcon, QAction
from ldap3 import Server, Connection, ALL, Tls, SUBTREE
from ldap3.core.exceptions import LDAPException

# Import will be used when running as part of the application
try:
    from helpers import domain_to_base_dn, get_app_stylesheet
    from Login import DOMAIN_CONFIG  # Import domain config from Login
    from UserEditor import UserWindow, UserOperation  # Import from new modular code
except ImportError:
    # Minimal imports for standalone testing
    def domain_to_base_dn(domain: str) -> str:
        parts = domain.split('.')
        return ','.join(f"DC={part}" for part in parts)
    
    def get_app_stylesheet():
        return ""
        
    # Define a default domain config for testing
    DOMAIN_CONFIG = {
        "CORP": ("corp.adenshomelab.xyz", [
            "SDMSRVDCP001.corp.adenshomelab.xyz",
        ]),
        "SDNM": ("sdnm.adenshomelab.xyz", [
            "SDNMSRVDCP001.sdnm.adenshomelab.xyz",
        ])
    }
    
    # Mock UserOperation enum
    class UserOperation:
        CREATE = 1
        EDIT = 2
    
    # Mock UserWindow class
    class UserWindow(QWidget):
        user_action_completed = pyqtSignal()
        
        def __init__(self, ldap_conn, mode=UserOperation.CREATE, user_dn=None, 
                    ou_list=None, current_domain=None, domains=None):
            super().__init__()


class DirectoryBrowser(QMainWindow):
    def __init__(self, login_domain, login_domain_dns, username, password, dc_fqdn, base_dn, port):
        """
        Initialize the directory browser
        
        Args:
            login_domain: NetBIOS domain name (e.g., "CORP")
            login_domain_dns: FQDN domain name (e.g., "corp.adenshomelab.xyz")
            username: Username without domain prefix
            password: User password
            dc_fqdn: Domain controller FQDN
            base_dn: Base DN for searches
            port: LDAP port (636 or 3269 for Global Catalog)
        """
        super().__init__()
        self.login_domain = login_domain
        self.login_domain_dns = login_domain_dns
        self.username = username
        self.password = password
        self.dc_fqdn = dc_fqdn
        self.base_dn = base_dn  # Naming context for OU browsing
        self.port = port
        self.conn = None
        self.server = None
        
        # Use domain config from Login
        self.domains = {netbios: fqdn for netbios, (fqdn, _) in DOMAIN_CONFIG.items()}
        
        # Determine which domain's DC we're connected to
        self.connected_domain = self.determine_connected_domain()
        
        self.setWindowTitle("Active Directory Management")
        self.setMinimumWidth(900)
        self.setMinimumHeight(600)
        self.setup_ui()
        self.setup_toolbar()
        self.setup_statusbar()
        self.create_connection()
        
        # Load OUs after a brief delay to ensure connection is ready
        QTimer.singleShot(100, self.load_ous)

    def determine_connected_domain(self):
        """Determine which domain we're connected to based on the DC"""
        # Default to login domain
        connected_domain = self.login_domain_dns
        
        # Check if the DC is in a different domain
        for netbios, (fqdn, dc_list) in DOMAIN_CONFIG.items():
            if any(dc.lower() == self.dc_fqdn.lower() for dc in dc_list):
                connected_domain = fqdn
                break
                
        return connected_domain

    def setup_ui(self):
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        main_layout = QVBoxLayout(self.central_widget)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(10)
        
        # Domain selection and search bar in the top section
        top_bar = QHBoxLayout()
        
        # Domain selection
        domain_layout = QHBoxLayout()
        domain_label = QLabel("Domain:")
        domain_layout.addWidget(domain_label)
        
        self.domain_combo = QComboBox()
        # Populate with all domains from DOMAIN_CONFIG
        for netbios, (fqdn, _) in DOMAIN_CONFIG.items():
            self.domain_combo.addItem(f"{netbios} ({fqdn})", fqdn)
            
        # Select the connected domain
        connected_idx = self.domain_combo.findData(self.connected_domain)
        if connected_idx >= 0:
            self.domain_combo.setCurrentIndex(connected_idx)
            
        self.domain_combo.currentIndexChanged.connect(self.update_domain)
        domain_layout.addWidget(self.domain_combo)
        top_bar.addLayout(domain_layout)
        
        top_bar.addStretch()
        
        # Search bar
        search_layout = QHBoxLayout()
        self.search_edit = QLineEdit()
        self.search_edit.setObjectName("searchBar")
        self.search_edit.setPlaceholderText("Search AD (name, samAccountName, etc.)")
        self.search_edit.setMinimumWidth(300)
        self.search_button = QPushButton("Search")
        self.search_button.clicked.connect(self.perform_search)
        self.search_edit.returnPressed.connect(self.perform_search)
        search_layout.addWidget(self.search_edit)
        search_layout.addWidget(self.search_button)
        top_bar.addLayout(search_layout)
        
        main_layout.addLayout(top_bar)
        
        # Tab widget to separate browsing and search results
        self.tab_widget = QTabWidget()
        
        # Browser tab
        browser_widget = QWidget()
        browser_layout = QVBoxLayout(browser_widget)
        
        # Splitter: left is OU tree, right is object table
        self.splitter = QSplitter(Qt.Orientation.Horizontal)
        
        # Left side: OU tree
        left_widget = QWidget()
        left_layout = QVBoxLayout(left_widget)
        left_layout.setContentsMargins(0, 0, 0, 0)
        
        ou_label = QLabel("Organizational Units:")
        left_layout.addWidget(ou_label)
        
        self.ou_tree = QTreeWidget()
        self.ou_tree.setHeaderLabel("Organizational Units")
        self.ou_tree.itemClicked.connect(self.on_ou_selected)
        left_layout.addWidget(self.ou_tree)
        
        # Right side: Object table with controls
        right_widget = QWidget()
        right_layout = QVBoxLayout(right_widget)
        right_layout.setContentsMargins(0, 0, 0, 0)
        
        object_label = QLabel("Objects:")
        right_layout.addWidget(object_label)
        
        self.object_table = QTableWidget()
        self.object_table.setColumnCount(3)
        self.object_table.setHorizontalHeaderLabels(["Display Name", "Type", "DN"])
        self.object_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.object_table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.object_table.cellDoubleClicked.connect(self.on_object_double_clicked)
        self.object_table.verticalHeader().setDefaultSectionSize(30)  # Taller rows
        self.object_table.setAlternatingRowColors(True)  # Better visual separation
        right_layout.addWidget(self.object_table)
        
        # Action buttons for the right panel
        button_layout = QHBoxLayout()
        self.create_user_button = QPushButton("Create New User")
        self.create_user_button.clicked.connect(self.on_create_new_user)
        button_layout.addWidget(self.create_user_button)
        
        self.edit_button = QPushButton("Edit Selected")
        self.edit_button.clicked.connect(self.on_edit_selected)
        self.edit_button.setEnabled(False)  # Only enable when an item is selected
        button_layout.addWidget(self.edit_button)
        
        self.object_table.itemSelectionChanged.connect(self.update_button_states)
        
        right_layout.addLayout(button_layout)
        
        # Add widgets to splitter
        self.splitter.addWidget(left_widget)
        self.splitter.addWidget(right_widget)
        self.splitter.setStretchFactor(0, 1)
        self.splitter.setStretchFactor(1, 2)
        
        browser_layout.addWidget(self.splitter)
        
        # Add browser tab
        self.tab_widget.addTab(browser_widget, "Browse")
        
        # Search results tab (will be populated when search is performed)
        self.search_widget = QWidget()
        search_layout = QVBoxLayout(self.search_widget)
        
        self.search_results_label = QLabel("No search results")
        search_layout.addWidget(self.search_results_label)
        
        self.search_results_table = QTableWidget()
        self.search_results_table.setColumnCount(4)
        self.search_results_table.setHorizontalHeaderLabels(["Display Name", "SAM Account", "Type", "Location"])
        self.search_results_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.search_results_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.search_results_table.cellDoubleClicked.connect(self.on_search_result_double_clicked)
        self.search_results_table.verticalHeader().setDefaultSectionSize(30)  # Taller rows
        self.search_results_table.setAlternatingRowColors(True)  # Better visual separation
        search_layout.addWidget(self.search_results_table)
        
        self.tab_widget.addTab(self.search_widget, "Search Results")
        
        main_layout.addWidget(self.tab_widget)

    def setup_toolbar(self):
        toolbar = QToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(24, 24))
        toolbar.setMovable(False)
        self.addToolBar(toolbar)
        
        # Refresh action
        refresh_action = QAction("Refresh", self)
        refresh_action.triggered.connect(self.refresh_view)
        toolbar.addAction(refresh_action)
        
        toolbar.addSeparator()
        
        # Create user action
        new_user_action = QAction("New User", self)
        new_user_action.triggered.connect(self.on_create_new_user)
        toolbar.addAction(new_user_action)
        
        # Add spacer to push help to the right
        spacer = QWidget()
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Expanding)
        toolbar.addWidget(spacer)
        
        # Help action
        help_action = QAction("Help", self)
        toolbar.addAction(help_action)

    def setup_statusbar(self):
        self.statusbar = QStatusBar()
        self.setStatusBar(self.statusbar)
        self.statusbar.showMessage(f"Connected to {self.connected_domain} via {self.dc_fqdn}")

    def create_connection(self):
        tls_config = Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLSv1_2)
        try:
            self.server = Server(f"ldaps://{self.dc_fqdn}", port=self.port, tls=tls_config, get_info=ALL)
            bind_user = f"{self.username}@{self.login_domain_dns}"
            self.conn = Connection(self.server, user=bind_user, password=self.password, auto_bind=True)
            
            # Get the base_dn for the current domain
            self.base_dn = domain_to_base_dn(self.connected_domain)
            
            self.statusbar.showMessage(f"Connected to {self.connected_domain} via {self.dc_fqdn}")
        except LDAPException as e:
            QMessageBox.critical(self, "LDAP Error", f"Failed to connect: {e}")
            self.conn = None
            self.statusbar.showMessage("Connection failed")

    def load_ous(self):
        if not self.conn:
            self.statusbar.showMessage("Not connected - cannot load OUs")
            return
            
        self.statusbar.showMessage(f"Loading organizational units for {self.connected_domain}...")
        QApplication.processEvents()
        
        # Make sure base_dn is set to the correct domain
        if not self.base_dn.lower().startswith("dc="):
            self.base_dn = domain_to_base_dn(self.connected_domain)
            
        search_filter = "(objectClass=organizationalUnit)"
        try:
            # Use the connected domain's DN for searching
            self.conn.search(search_base=self.base_dn, search_filter=search_filter,
                             search_scope=SUBTREE, attributes=["ou", "distinguishedName", "name"])
        except LDAPException as e:
            QMessageBox.critical(self, "LDAP Error", f"Failed to search for OUs: {e}")
            self.statusbar.showMessage("Error loading OUs")
            return

        self.ou_tree.clear()
        self.ou_items = {}
        
        # Debug - check what we got back
        if not self.conn.entries:
            self.statusbar.showMessage(f"No OUs found for {self.connected_domain} ({self.base_dn})")
            return
            
        # Process the entries
        for entry in self.conn.entries:
            if not hasattr(entry, "distinguishedName"):
                continue
                
            dn = entry.distinguishedName.value
            
            # Get OU name from the entry
            if hasattr(entry, "ou"):
                ou_name = entry.ou.value
            elif hasattr(entry, "name"):
                ou_name = entry.name.value
            else:
                # Extract from DN as fallback
                ou_name = dn.split(',')[0].replace('OU=', '')
                
            item = QTreeWidgetItem([ou_name])
            item.setData(0, Qt.ItemDataRole.UserRole, dn)
            self.ou_items[dn] = item

        # Build tree hierarchy
        for dn, item in self.ou_items.items():
            if "," in dn:
                parent_dn = dn.split(",", 1)[1]
                if parent_dn in self.ou_items:
                    self.ou_items[parent_dn].addChild(item)
                else:
                    self.ou_tree.addTopLevelItem(item)
            else:
                self.ou_tree.addTopLevelItem(item)
                
        self.ou_tree.expandAll()  # Expand all nodes for better visibility
        self.statusbar.showMessage(f"Loaded {len(self.ou_items)} organizational units for {self.connected_domain}")

    def update_domain(self):
        """Switch to a different domain when selected in dropdown"""
        domain_idx = self.domain_combo.currentIndex()
        if domain_idx < 0:
            return
            
        new_domain = self.domain_combo.itemData(domain_idx)
        if not new_domain or new_domain == self.connected_domain:
            return
            
        self.statusbar.showMessage(f"Switching to {new_domain}...")
        QApplication.processEvents()
        
        # Find the netbios name for this domain
        new_netbios = None
        for netbios, (fqdn, _) in DOMAIN_CONFIG.items():
            if fqdn.lower() == new_domain.lower():
                new_netbios = netbios
                break
                
        if not new_netbios:
            # Extract from FQDN as fallback
            new_netbios = new_domain.split('.')[0].upper()
        
        # Use the existing DC for the connection, but specify GC port
        tls_config = Tls(validate=ssl.CERT_REQUIRED, version=ssl.PROTOCOL_TLSv1_2)
        try:
            if self.conn:
                self.conn.unbind()
                
            # When switching to a new domain, use Global Catalog
            self.server = Server(f"ldaps://{self.dc_fqdn}", port=3269, tls=tls_config, get_info=ALL)
            bind_user = f"{self.username}@{self.login_domain_dns}"
            self.conn = Connection(self.server, user=bind_user, password=self.password, auto_bind=True)
            
            # Update domain info
            self.connected_domain = new_domain
            self.base_dn = domain_to_base_dn(new_domain)
            
            # Reload OUs for the new domain
            self.load_ous()
            
            self.statusbar.showMessage(f"Connected to {new_domain} via {self.dc_fqdn}")
        except LDAPException as e:
            QMessageBox.critical(self, "LDAP Error", f"Failed to connect to new domain: {e}")
            self.statusbar.showMessage(f"Failed to connect to {new_domain}")

    def on_ou_selected(self, item, column):
        ou_dn = item.data(0, Qt.ItemDataRole.UserRole)
        self.statusbar.showMessage(f"Loading objects from {item.text(0)}...")
        QApplication.processEvents()
        
        search_filter = "(|(objectCategory=person)(objectCategory=computer)(objectCategory=group))"
        try:
            self.conn.search(search_base=ou_dn, search_filter=search_filter,
                             search_scope=SUBTREE,
                             attributes=["sAMAccountName", "displayName", "objectCategory", "distinguishedName", "cn"])
        except LDAPException as e:
            QMessageBox.critical(self, "LDAP Error", f"Failed to search for objects: {e}")
            self.statusbar.showMessage("Error loading objects")
            return

        entries = self.conn.entries
        self.object_table.setRowCount(0)
        
        for entry in entries:
            row = self.object_table.rowCount()
            self.object_table.insertRow(row)
            
            # Use displayName if available, otherwise fallback to sAMAccountName or CN
            if hasattr(entry, "displayName") and entry.displayName.value:
                name = entry.displayName.value
            elif hasattr(entry, "sAMAccountName") and entry.sAMAccountName.value:
                name = entry.sAMAccountName.value
            elif hasattr(entry, "cn"):
                name = entry.cn.value
            else:
                name = "Unknown"
                
            obj_cat = entry.objectCategory.value if hasattr(entry, "objectCategory") else ""
            # Simplify object category display
            if "person" in obj_cat.lower():
                obj_type = "User"
            elif "computer" in obj_cat.lower():
                obj_type = "Computer"
            elif "group" in obj_cat.lower():
                obj_type = "Group"
            else:
                obj_type = obj_cat.split(",")[0].replace("CN=", "")
                
            dn = entry.distinguishedName.value if hasattr(entry, "distinguishedName") else ""
            
            self.object_table.setItem(row, 0, QTableWidgetItem(name))
            self.object_table.setItem(row, 1, QTableWidgetItem(obj_type))
            self.object_table.setItem(row, 2, QTableWidgetItem(dn))
            
        self.statusbar.showMessage(f"Loaded {self.object_table.rowCount()} objects from {item.text(0)}")

    def on_object_double_clicked(self, row, column):
        """Handle double-clicking on an object"""
        type_item = self.object_table.item(row, 1)
        dn_item = self.object_table.item(row, 2)
        
        if not type_item or not dn_item:
            return
            
        obj_type = type_item.text()
        dn = dn_item.text()
        
        # Open the appropriate editor based on object type
        if obj_type == "User":
            # Use the new UserWindow with EDIT mode
            self.edit_user_window = UserWindow(
                ldap_conn=self.conn,
                mode=UserOperation.EDIT,
                user_dn=dn,
                current_domain=self.connected_domain,
                domains=self.domains
            )
            self.edit_user_window.user_action_completed.connect(self.refresh_view)
            self.edit_user_window.show()
        else:
            # For now, just show information about other object types
            name_item = self.object_table.item(row, 0)
            name = name_item.text() if name_item else "Unknown"
            
            info_text = f"Selected {obj_type}:\n\nName: {name}\nDN: {dn}"
            QMessageBox.information(self, f"Edit {obj_type}", info_text)

    def on_edit_selected(self):
        """Handle editing of a selected object"""
        selected_rows = self.object_table.selectedItems()
        if not selected_rows:
            return
            
        row = selected_rows[0].row()
        name_item = self.object_table.item(row, 0)
        type_item = self.object_table.item(row, 1)
        dn_item = self.object_table.item(row, 2)
        
        if not all([name_item, type_item, dn_item]):
            return
            
        name = name_item.text()
        obj_type = type_item.text()
        dn = dn_item.text()
        
        # Open the appropriate editor based on object type
        if obj_type == "User":
            # Use the new UserWindow with EDIT mode
            self.edit_user_window = UserWindow(
                ldap_conn=self.conn,
                mode=UserOperation.EDIT,
                user_dn=dn,
                current_domain=self.connected_domain,
                domains=self.domains
            )
            self.edit_user_window.user_action_completed.connect(self.refresh_view)
            self.edit_user_window.show()
        else:
            # For now, just show information about other object types
            info_text = f"Selected {obj_type}:\n\nName: {name}\nDN: {dn}"
            QMessageBox.information(self, f"Edit {obj_type}", info_text)

    def update_button_states(self):
        self.edit_button.setEnabled(len(self.object_table.selectedItems()) > 0)

    def perform_search(self):
        search_term = self.search_edit.text().strip()
        if not search_term:
            QMessageBox.information(self, "Search", "Please enter a search term")
            return
            
        self.statusbar.showMessage(f"Searching for '{search_term}'...")
        QApplication.processEvents()
        
        # Construct search filter for name, sAMAccountName, or CN
        search_filter = f"(|(cn=*{search_term}*)(sAMAccountName=*{search_term}*)(name=*{search_term}*)(displayName=*{search_term}*))"
        
        try:
            self.conn.search(search_base=self.base_dn, search_filter=search_filter,
                           search_scope=SUBTREE,
                           attributes=["displayName", "cn", "sAMAccountName", "objectCategory", "distinguishedName"])
        except LDAPException as e:
            QMessageBox.critical(self, "LDAP Error", f"Failed to perform search: {e}")
            self.statusbar.showMessage("Search failed")
            return
            
        entries = self.conn.entries
        self.search_results_table.setRowCount(0)
        
        for entry in entries:
            row = self.search_results_table.rowCount()
            self.search_results_table.insertRow(row)
            
            # Use displayName for name column
            name = entry.displayName.value if hasattr(entry, "displayName") and entry.displayName.value else ""
            if not name:
                name = entry.cn.value if hasattr(entry, "cn") else ""
                
            # Get SAM account name (keep this for the sam column)
            sam = entry.sAMAccountName.value if hasattr(entry, "sAMAccountName") else ""
            
            # Get object type
            obj_cat = entry.objectCategory.value if hasattr(entry, "objectCategory") else ""
            if "person" in obj_cat.lower():
                obj_type = "User"
            elif "computer" in obj_cat.lower():
                obj_type = "Computer"
            elif "group" in obj_cat.lower():
                obj_type = "Group"
            else:
                obj_type = obj_cat.split(",")[0].replace("CN=", "")
                
            # Get location (OU path)
            dn = entry.distinguishedName.value if hasattr(entry, "distinguishedName") else ""
            ou_path = ','.join(dn.split(',')[1:])  # Remove the CN part
            
            self.search_results_table.setItem(row, 0, QTableWidgetItem(name))
            self.search_results_table.setItem(row, 1, QTableWidgetItem(sam))
            self.search_results_table.setItem(row, 2, QTableWidgetItem(obj_type))
            self.search_results_table.setItem(row, 3, QTableWidgetItem(ou_path))
            
        result_count = self.search_results_table.rowCount()
        self.search_results_label.setText(f"Found {result_count} result{'s' if result_count != 1 else ''} for '{search_term}'")
        self.statusbar.showMessage(f"Search completed, found {result_count} matches")
        
        # Switch to search results tab
        self.tab_widget.setCurrentIndex(1)

    def on_search_result_double_clicked(self, row, column):
        """Handle double-clicking a search result"""
        type_item = self.search_results_table.item(row, 2)  # Assuming column 2 is type
        
        if not type_item:
            return
            
        obj_type = type_item.text()
        
        # For users, open the edit window
        if obj_type == "User":
            # Get the DN from the search results
            dn = ""
            name_item = self.search_results_table.item(row, 0)
            sam_item = self.search_results_table.item(row, 1)
            location_item = self.search_results_table.item(row, 3)
            
            if location_item:
                # We need to find the actual DN for this object by doing a search
                name = name_item.text() if name_item else ""
                sam = sam_item.text() if sam_item else ""
                
                # Use SAM account for searching as it's more reliable
                if sam:
                    search_filter = f"(sAMAccountName={sam})"
                elif name:
                    search_filter = f"(displayName={name})"
                else:
                    return
                    
                try:
                    self.conn.search(
                        search_base=self.base_dn,
                        search_filter=search_filter,
                        search_scope=SUBTREE,
                        attributes=["distinguishedName"]
                    )
                    
                    if self.conn.entries and hasattr(self.conn.entries[0], "distinguishedName"):
                        dn = self.conn.entries[0].distinguishedName.value
                        
                        # Now we have the DN, open the edit window with the new UserWindow
                        self.edit_user_window = UserWindow(
                            ldap_conn=self.conn,
                            mode=UserOperation.EDIT,
                            user_dn=dn,
                            current_domain=self.connected_domain,
                            domains=self.domains
                        )
                        self.edit_user_window.user_action_completed.connect(self.refresh_view)
                        self.edit_user_window.show()
                    else:
                        QMessageBox.warning(self, "Object Not Found", "Could not find the object's distinguished name.")
                        
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to get object details: {e}")
        else:
            # For non-user objects
            name_item = self.search_results_table.item(row, 0)
            name = name_item.text() if name_item else "Unknown"
            
            QMessageBox.information(self, f"{obj_type} Details", f"Details for {name}")

    def on_create_new_user(self):
        """Handle request to create a new user"""
        # Make sure we have OUs to work with
        if not hasattr(self, 'ou_items') or not self.ou_items:
            QMessageBox.warning(self, "No OUs", "No organizational units available for user creation.")
            return
            
        ou_list = []
        def add_items(item):
            ou_dn = item.data(0, Qt.ItemDataRole.UserRole)
            ou_list.append((item.text(0), ou_dn))
            for i in range(item.childCount()):
                add_items(item.child(i))
                
        for i in range(self.ou_tree.topLevelItemCount()):
            add_items(self.ou_tree.topLevelItem(i))
            
        # If no OUs found, show error
        if not ou_list:
            QMessageBox.warning(self, "No OUs", "No organizational units available for user creation.")
            return
            
        # Create the new user window with our new UserWindow in CREATE mode
        self.create_user_window = UserWindow(
            ldap_conn=self.conn,
            mode=UserOperation.CREATE,
            ou_list=ou_list,
            current_domain=self.connected_domain,
            domains=self.domains
        )
        self.create_user_window.user_action_completed.connect(self.on_user_created)
        self.create_user_window.show()

    def on_user_created(self):
        """Called when a user is created or updated"""
        # Refresh the current view after user creation/update
        self.refresh_view()
        self.statusbar.showMessage("User operation completed successfully")

    def on_search_result_double_clicked(self, row, column):
        """Handle double-clicking a search result"""
        type_item = self.search_results_table.item(row, 2)  # Assuming column 2 is type
        
        if not type_item:
            return
            
        obj_type = type_item.text()
        
        # For users, open the edit window
        if obj_type == "User":
            # Get the DN from the search results
            dn = ""
            name_item = self.search_results_table.item(row, 0)
            sam_item = self.search_results_table.item(row, 1)
            location_item = self.search_results_table.item(row, 3)
            
            if location_item:
                # We need to find the actual DN for this object by doing a search
                name = name_item.text() if name_item else ""
                sam = sam_item.text() if sam_item else ""
                
                # Use SAM account for searching as it's more reliable
                if sam:
                    search_filter = f"(sAMAccountName={sam})"
                elif name:
                    search_filter = f"(displayName={name})"
                else:
                    return
                    
                try:
                    self.conn.search(
                        search_base=self.base_dn,
                        search_filter=search_filter,
                        search_scope=SUBTREE,
                        attributes=["distinguishedName"]
                    )
                    
                    if self.conn.entries and hasattr(self.conn.entries[0], "distinguishedName"):
                        dn = self.conn.entries[0].distinguishedName.value
                        
                        # Now we have the DN, open the edit window with the new UserWindow
                        self.edit_user_window = UserWindow(
                            ldap_conn=self.conn,
                            mode=UserOperation.EDIT,
                            user_dn=dn,
                            current_domain=self.connected_domain,
                            domains=self.domains
                        )
                        self.edit_user_window.user_action_completed.connect(self.refresh_view)
                        self.edit_user_window.show()
                    else:
                        QMessageBox.warning(self, "Object Not Found", "Could not find the object's distinguished name.")
                        
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to get object details: {e}")
        else:
            # For non-user objects
            name_item = self.search_results_table.item(row, 0)
            name = name_item.text() if name_item else "Unknown"
            
            QMessageBox.information(self, f"{obj_type} Details", f"Details for {name}")

    def refresh_view(self):
        """Refresh the current view"""
        # Reload OUs first
        self.load_ous()
        
        # Then refresh objects if an OU is selected
        selected_items = self.ou_tree.selectedItems()
        if selected_items:
            self.on_ou_selected(selected_items[0], 0)
        
        self.statusbar.showMessage("View refreshed")

    def closeEvent(self, event):
        """Handle window close event"""
        if self.conn:
            self.conn.unbind()
        event.accept()


# Allow running this file directly for testing
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyleSheet(get_app_stylesheet())
    
    # Minimal mock data for testing
    browser = DirectoryBrowser(
        login_domain="CORP",
        login_domain_dns="corp.adenshomelab.xyz",
        username="testuser",
        password="testpass",
        dc_fqdn="SDMSRVDCP001.corp.adenshomelab.xyz",
        base_dn="DC=corp,DC=adenshomelab,DC=xyz",
        port=636
    )
    browser.show()
    
    sys.exit(app.exec())