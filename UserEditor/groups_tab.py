"""
Group membership management tab for Active Directory user management
"""

from PyQt6.QtWidgets import (
    QWidget, QLabel, QLineEdit, QPushButton, QScrollArea, QCheckBox,
    QVBoxLayout, QHBoxLayout, QListWidget, QMessageBox, QListWidgetItem
)
from PyQt6.QtCore import Qt, QTimer
from ldap3 import SUBTREE


class CollapsibleGroupBox(QWidget):
    """A custom collapsible section that can be expanded/collapsed"""
    def __init__(self, title, parent=None):
        super().__init__(parent)
        self.setLayout(QVBoxLayout())
        self.layout().setContentsMargins(0, 0, 0, 0)
        self.layout().setSpacing(0)
        
        # Header with toggle button
        self.header = QWidget()
        header_layout = QHBoxLayout()
        header_layout.setContentsMargins(5, 5, 5, 5)
        self.header.setLayout(header_layout)
        
        self.toggle_btn = QPushButton("+")
        self.toggle_btn.setFixedSize(24, 24)
        self.toggle_btn.clicked.connect(self.toggle_content)
        header_layout.addWidget(self.toggle_btn)
        
        title_label = QLabel(f"<b>{title}</b>")
        header_layout.addWidget(title_label)
        header_layout.addStretch()
        
        # Content area
        self.content = QWidget()
        self.content_layout = QVBoxLayout()
        self.content.setLayout(self.content_layout)
        self.content.setVisible(False)  # Hidden by default
        
        # Add widgets to main layout
        self.layout().addWidget(self.header)
        self.layout().addWidget(self.content)
        
        # Style
        self.header.setStyleSheet("background-color: #f0f0f0; border: 1px solid #ddd; border-radius: 4px;")
    
    def toggle_content(self):
        """Toggle the visibility of the content section"""
        is_visible = self.content.isVisible()
        self.content.setVisible(not is_visible)
        self.toggle_btn.setText("-" if not is_visible else "+")
    
    def addWidget(self, widget):
        """Add a widget to the content section"""
        self.content_layout.addWidget(widget)


class GroupsTab(QWidget):
    """Tab for managing group memberships for a user"""
    
    def __init__(self, parent=None, ldap_conn=None, base_dn=None):
        """
        Initialize the groups tab
        
        Args:
            parent: Parent widget
            ldap_conn: Active LDAP connection
            base_dn: Base Distinguished Name for the domain
        """
        super().__init__(parent)
        self.ldap_conn = ldap_conn
        self.base_dn = base_dn
        self.default_section = None
        self.all_groups = []
        self.selected_groups = []
        self.group_checkboxes = {}
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the UI components"""
        layout = QVBoxLayout(self)
        
        # Add a search bar for filtering groups
        search_layout = QHBoxLayout()
        search_label = QLabel("Search Groups:")
        self.search_edit = QLineEdit()
        self.search_edit.setPlaceholderText("Type to filter groups...")
        self.search_edit.textChanged.connect(self.filter_groups)
        search_layout.addWidget(search_label)
        search_layout.addWidget(self.search_edit)
        layout.addLayout(search_layout)
        
        # Create a scroll area for the groups list
        groups_scroll = QScrollArea()
        groups_scroll.setWidgetResizable(True)
        groups_scroll_content = QWidget()
        self.groups_list_layout = QVBoxLayout(groups_scroll_content)
        self.groups_list_layout.setAlignment(Qt.AlignmentFlag.AlignTop)
        groups_scroll.setWidget(groups_scroll_content)
        layout.addWidget(groups_scroll)
        
        # Add a refresh button and selection helpers
        button_layout = QHBoxLayout()
        self.refresh_btn = QPushButton("Refresh Groups")
        self.refresh_btn.clicked.connect(self.load_domain_groups)
        
        self.select_all_btn = QPushButton("Select All")
        self.select_all_btn.clicked.connect(lambda: self.toggle_all_groups(True))
        
        self.clear_all_btn = QPushButton("Clear All")
        self.clear_all_btn.clicked.connect(lambda: self.toggle_all_groups(False))
        
        button_layout.addWidget(self.refresh_btn)
        button_layout.addWidget(self.select_all_btn)
        button_layout.addWidget(self.clear_all_btn)
        layout.addLayout(button_layout)
        
        # Setup for editing mode
        self.edit_mode_layout = QVBoxLayout()
        self.list_widget = QListWidget()
        
        self.add_group_btn = QPushButton("Add Group")
        self.add_group_btn.clicked.connect(self.add_group)
        
        self.remove_group_btn = QPushButton("Remove Group")
        self.remove_group_btn.clicked.connect(self.remove_group)
        
        edit_buttons = QHBoxLayout()
        edit_buttons.addWidget(self.add_group_btn)
        edit_buttons.addWidget(self.remove_group_btn)
        
        self.edit_mode_layout.addWidget(QLabel("Current Group Memberships:"))
        self.edit_mode_layout.addWidget(self.list_widget)
        self.edit_mode_layout.addLayout(edit_buttons)
        
        # The edit mode widgets are hidden by default
        # They'll be shown when edit mode is activated
        
        # Set layout spacing
        layout.setSpacing(10)
        layout.setContentsMargins(10, 10, 10, 10)
        
    def get_selected_groups(self):
        """
        Get the selected groups
        
        Returns:
            List of selected group names
        """
        return self.selected_groups.copy()
    
    def set_selected_groups(self, groups):
        """
        Set the selected groups
        
        Args:
            groups: List of group names
        """
        self.selected_groups = groups.copy()
        # Update checkboxes if they exist
        for group_name, checkbox in self.group_checkboxes.items():
            checkbox.setChecked(group_name in self.selected_groups)
    
    def set_edit_mode(self, is_edit_mode, group_dns=None):
        """
        Switch between create mode (checkboxes) and edit mode (list view)
        
        Args:
            is_edit_mode: True for edit mode, False for create mode
            group_dns: List of group DNs for edit mode
        """
        if is_edit_mode:
            # Hide create mode widgets
            for i in reversed(range(self.layout().count())):
                item = self.layout().itemAt(i)
                if item and item.widget():
                    item.widget().setVisible(False)
            
            # Add edit mode widgets if not already there
            if self.edit_mode_layout.parent() is None:
                self.layout().addLayout(self.edit_mode_layout)
            
            # Show edit mode widgets
            for i in range(self.edit_mode_layout.count()):
                item = self.edit_mode_layout.itemAt(i)
                if item and item.widget():
                    item.widget().setVisible(True)
            
            # Populate with group names
            self.list_widget.clear()
            self.displayable_groups = []
            
            if group_dns:
                # Extract CN part (group name) from each DN
                for group_dn in group_dns:
                    if group_dn.startswith('CN='):
                        group_name = group_dn.split(',')[0].replace('CN=', '')
                        self.displayable_groups.append(group_name)
                        self.list_widget.addItem(group_name)
                    else:
                        self.displayable_groups.append(group_dn)
                        self.list_widget.addItem(group_dn)
        else:
            # Hide edit mode widgets
            for i in range(self.edit_mode_layout.count()):
                item = self.edit_mode_layout.itemAt(i)
                if item and item.widget():  # Check if item and widget exist
                    item.widget().setVisible(False)
            
            # Show create mode widgets
            for i in range(self.layout().count() - 1):  # -1 to exclude edit_mode_layout
                item = self.layout().itemAt(i)
                if item and item.widget():  # Check if item and widget exist
                    item.widget().setVisible(True)
            
            # Load domain groups if not already loaded
            if not self.all_groups:
                QTimer.singleShot(100, self.load_domain_groups)
    
    def load_domain_groups(self):
        """Load all groups from the current domain"""
        if not self.ldap_conn or not self.base_dn:
            QMessageBox.warning(self, "Error", "No active LDAP connection")
            return
        
        # Clear existing widgets
        for i in reversed(range(self.groups_list_layout.count())):
            widget = self.groups_list_layout.itemAt(i).widget()
            if widget:
                widget.deleteLater()
        self.group_checkboxes = {}
        self.all_groups = []
        
        # Define exact default group names (not partial matches)
        default_group_names = {
            "Domain Users", "Domain Admins", "Domain Computers", "Domain Controllers",
            "Schema Admins", "Enterprise Admins", "Group Policy Creator Owners",
            "Protected Users", "Cert Publishers", "RAS and IAS Servers",
            "Terminal Server License Servers", "Allowed RODC Password Replication Group",
            "Denied RODC Password Replication Group", "Read-only Domain Controllers",
            "Enterprise Read-only Domain Controllers", "Cloneable Domain Controllers",
            "DnsAdmins", "DnsUpdateProxy", "Administrators", "Users", "Guests",
            "Print Operators", "Backup Operators", "Replicator", "Remote Desktop Users",
            "Network Configuration Operators", "Performance Monitor Users",
            "Performance Log Users", "Distributed COM Users", "IIS_IUSRS",
            "Cryptographic Operators", "Event Log Readers", "Certificate Service DCOM Access"
        }
        
        # Define container paths that indicate default groups
        default_containers = [
            "CN=Builtin,", "CN=Users,", 
            "OU=Microsoft Exchange Security Groups,"
        ]
        
        try:
            # Search for all groups in the domain
            search_filter = "(objectClass=group)"
            self.ldap_conn.search(
                search_base=self.base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=["cn", "distinguishedName", "description", "groupType"]
            )
            
            # Sort groups alphabetically
            entries = sorted(self.ldap_conn.entries, key=lambda x: x.cn.value if hasattr(x, "cn") else "")
            
            # Categorize groups
            default_groups = []
            custom_groups = []
            
            for entry in entries:
                if hasattr(entry, "cn") and hasattr(entry, "distinguishedName"):
                    group_name = entry.cn.value
                    group_dn = entry.distinguishedName.value
                    group_desc = entry.description.value if hasattr(entry, "description") and entry.description.value else ""
                    
                    # Create group info dictionary
                    group_info = {
                        "name": group_name,
                        "dn": group_dn,
                        "description": group_desc
                    }
                    
                    # Check if it's a default group
                    if group_name in default_group_names or any(
                        container in group_dn for container in default_containers):
                        default_groups.append(group_info)
                    else:
                        custom_groups.append(group_info)
                    
                    self.all_groups.append(group_info)
            
            # Add custom groups directly
            if custom_groups:
                # Add a label for custom groups
                custom_label = QLabel("<b>Custom Groups</b>")
                self.groups_list_layout.addWidget(custom_label)
                
                for group_info in custom_groups:
                    group_name = group_info["name"]
                    group_desc = group_info["description"]
                    
                    # Create checkbox with tooltip
                    checkbox = QCheckBox(group_name)
                    if group_desc:
                        checkbox.setToolTip(group_desc)
                        
                    # Check if this group is in selected_groups
                    checkbox.setChecked(group_name in self.selected_groups)
                    checkbox.stateChanged.connect(self.update_selected_groups)
                    
                    self.groups_list_layout.addWidget(checkbox)
                    self.group_checkboxes[group_name] = checkbox
                    
            # Add default groups in a collapsible section
            if default_groups:
                # Create collapsible section for default groups
                default_section = CollapsibleGroupBox("Default Domain Groups")
                self.default_section = default_section  # Store reference for filtering
                
                for group_info in default_groups:
                    group_name = group_info["name"]
                    group_desc = group_info["description"]
                    
                    # Create checkbox with tooltip
                    checkbox = QCheckBox(group_name)
                    if group_desc:
                        checkbox.setToolTip(group_desc)
                        
                    # Check if this group is in selected_groups
                    checkbox.setChecked(group_name in self.selected_groups)
                    checkbox.stateChanged.connect(self.update_selected_groups)
                    
                    default_section.addWidget(checkbox)
                    self.group_checkboxes[group_name] = checkbox
                    
                self.groups_list_layout.addWidget(default_section)
                        
        except Exception as e:
            QMessageBox.warning(self, "Error Loading Groups", f"Failed to load domain groups: {e}")
    
    def filter_groups(self):
        """Filter groups based on search text"""
        search_text = self.search_edit.text().lower()
        
        # Keep track if we need to expand default groups section
        show_default_groups = False
        matching_default_count = 0
        
        # Process all checkboxes
        for group_name, checkbox in self.group_checkboxes.items():
            # Get the group info
            group_info = next((g for g in self.all_groups if g["name"] == group_name), None)
            if not group_info:
                continue
                
            group_desc = group_info["description"]
            
            # Check if the group matches the search
            matches = (search_text in group_name.lower() or 
                      (group_desc and search_text in group_desc.lower()))
            
            # Set visibility based on search match
            checkbox.setVisible(matches)
            
            # Determine if it's in the default section based on parent
            parent = checkbox.parent()
            if parent == self.default_section.content:
                if matches:
                    show_default_groups = True
                    matching_default_count += 1
        
        # Handle default section visibility
        if hasattr(self, 'default_section'):
            if search_text and show_default_groups:
                self.default_section.toggle_content() if not self.default_section.content.isVisible() else None
                self.default_section.header.setVisible(True)
            elif search_text:
                self.default_section.header.setVisible(False)
            else:
                self.default_section.header.setVisible(True)
                self.default_section.content.setVisible(False)
                self.default_section.toggle_btn.setText("+")
    
    def toggle_all_groups(self, checked):
        """Select or deselect all visible groups"""
        for checkbox in self.group_checkboxes.values():
            if checkbox.isVisible():
                checkbox.setChecked(checked)
        
        self.update_selected_groups()
    
    def update_selected_groups(self):
        """Update the selected_groups list based on checkboxes"""
        self.selected_groups = []
        
        for group_name, checkbox in self.group_checkboxes.items():
            if checkbox.isChecked():
                self.selected_groups.append(group_name)
    
    def add_group(self):
        """
        Add user to a group (placeholder for edit mode)
        Would normally open a group selection dialog
        """
        QMessageBox.information(self, "Add Group", "Group selection dialog would appear here")
    
    def remove_group(self):
        """Remove user from a selected group (in edit mode)"""
        selected_items = self.list_widget.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select a group to remove")
            return
        
        group_name = selected_items[0].text()
        reply = QMessageBox.question(
            self, 
            "Confirm Removal", 
            f"Remove user from group {group_name}?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        
        if reply == QMessageBox.StandardButton.Yes:
            # Find the DN for this group
            group_dn = None
            for dn in getattr(self, 'groups', []):
                if dn.startswith(f'CN={group_name},'):
                    group_dn = dn
                    break
                    
            # Update the list
            self.list_widget.takeItem(self.list_widget.row(selected_items[0]))
            
            # Store the group DN for processing in the parent window
            if group_dn:
                if not hasattr(self, 'removed_groups'):
                    self.removed_groups = []
                self.removed_groups.append(group_dn)
            else:
                QMessageBox.warning(self, "Group Not Found", f"Could not find DN for group {group_name}")
    
    def get_removed_groups(self):
        """Get the list of removed groups"""
        return getattr(self, 'removed_groups', [])
    
    def get_selected_groups(self):
        """
        Get the selected groups (different in create vs edit mode)
        
        Returns:
            List of selected group names
        """
        # Edit mode - use list widget items
        if hasattr(self, 'list_widget') and self.list_widget.isVisible():
            result = []
            for i in range(self.list_widget.count()):
                result.append(self.list_widget.item(i).text())
            return result
        # Create mode - use checkboxes
        else:
            return self.selected_groups
