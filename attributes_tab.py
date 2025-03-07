"""
User attributes management tab for Active Directory user management
"""

from PyQt6.QtWidgets import (
    QWidget, QTableWidget, QTableWidgetItem, QHeaderView, QScrollArea, QLabel,
    QPushButton, QVBoxLayout, QHBoxLayout, QDialog, QLineEdit, QTextEdit,
    QFormLayout, QMessageBox
)
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont


class AttributesTab(QWidget):
    """Tab for displaying and editing LDAP attributes of a user"""
    
    def __init__(self, parent=None, ldap_conn=None, base_dn=None):
        """
        Initialize the attributes tab
        
        Args:
            parent: Parent widget
            ldap_conn: Active LDAP connection
            base_dn: Base Distinguished Name for the domain
        """
        super().__init__(parent)
        self.ldap_conn = ldap_conn
        self.base_dn = base_dn
        self.custom_attributes = {}
        self.setup_ui()
        
    def setup_ui(self):
        """Setup the UI components"""
        layout = QVBoxLayout(self)
        
        # Add a table to display all attributes
        self.attributes_table = QTableWidget()
        self.attributes_table.setColumnCount(2)
        self.attributes_table.setHorizontalHeaderLabels(["Attribute", "Value"])
        self.attributes_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self.attributes_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.attributes_table.verticalHeader().setDefaultSectionSize(45)  # Taller rows
        self.attributes_table.setAlternatingRowColors(True)
        self.attributes_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        
        # Make the attributes table scrollable
        scroll_area = QScrollArea()
        scroll_area.setWidget(self.attributes_table)
        scroll_area.setWidgetResizable(True)
        layout.addWidget(scroll_area)
        
        # Add buttons for editing attributes
        button_layout = QHBoxLayout()
        
        self.edit_button = QPushButton("Edit Selected")
        self.edit_button.clicked.connect(self.edit_attribute)
        button_layout.addWidget(self.edit_button)
        
        self.clear_button = QPushButton("Clear Selected")
        self.clear_button.clicked.connect(self.clear_attribute)
        button_layout.addWidget(self.clear_button)
        
        layout.addLayout(button_layout)
        
        # Set layout spacing
        layout.setSpacing(10)
        layout.setContentsMargins(10, 10, 10, 10)
    
    def get_attributes(self):
        """
        Get the current attributes
        
        Returns:
            Dictionary of attribute name:value pairs
        """
        return self.custom_attributes.copy()
    
    def set_attributes(self, attributes):
        """
        Set the attributes to display
        
        Args:
            attributes: Dictionary of attribute name:value pairs
        """
        self.custom_attributes = attributes.copy()
        self.populate_attributes_table()
    
    def populate_attributes_table(self, schema_attrs=None):
        """
        Populate the attributes table with all attributes
        
        Args:
            schema_attrs: Optional list of schema attributes to include
        """
        self.attributes_table.setRowCount(0)
        
        # Use provided schema attributes or current custom attributes
        if schema_attrs is None:
            schema_attrs = list(self.custom_attributes.keys())
            
        # Sort attributes alphabetically for easier viewing
        schema_attrs = sorted(schema_attrs)
        
        for attr_name in schema_attrs:
            row = self.attributes_table.rowCount()
            self.attributes_table.insertRow(row)
            
            # Add attribute name
            self.attributes_table.setItem(row, 0, QTableWidgetItem(attr_name))
            
            # Add attribute value
            value = self.custom_attributes.get(attr_name, "")
            if isinstance(value, list):
                # For multi-valued attributes, join with newlines
                display_value = "\n".join(str(v) for v in value) if value else ""
            else:
                display_value = str(value)
                
            value_item = QTableWidgetItem(display_value)
            self.attributes_table.setItem(row, 1, value_item)
            
            # Adjust row height based on content
            if "\n" in display_value:
                # Count newlines and set appropriate height
                line_count = display_value.count("\n") + 1
                # Set a minimum of 30 pixels per line, max 5 lines visible at once
                height = min(line_count, 5) * 30
                self.attributes_table.setRowHeight(row, height)
    
    def edit_attribute(self):
        """Edit the selected attribute"""
        selected_items = self.attributes_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select an attribute to edit")
            return
        
        # Get the attribute name
        row = selected_items[0].row()
        attr_name = self.attributes_table.item(row, 0).text()
        current_value = self.custom_attributes.get(attr_name, "")
        
        # Create a dialog for editing
        dialog = QDialog(self)
        dialog.setWindowTitle(f"Edit Attribute: {attr_name}")
        dialog.setMinimumWidth(550)  # Wider dialog
        dialog.setMinimumHeight(350)  # Taller dialog
        
        layout = QVBoxLayout()
        layout.setContentsMargins(20, 20, 20, 20)  # Add more padding
        layout.setSpacing(15)  # More space between elements
        
        # Add description label
        desc_label = QLabel(f"Editing attribute: {attr_name}")
        desc_font = QFont()
        desc_font.setBold(True)
        desc_font.setPointSize(11)
        desc_label.setFont(desc_font)
        layout.addWidget(desc_label)
        
        # Add input field based on attribute type
        if isinstance(current_value, list):
            # Multi-valued attribute
            value_edit = QTextEdit()
            value_edit.setMinimumHeight(200)  # Larger text edit area
            value_edit.setFont(QFont("Courier New", 10))  # Monospaced font
            value_edit.setPlainText("\n".join(str(v) for v in current_value))
        else:
            # Single-valued attribute
            value_edit = QLineEdit(str(current_value))
            value_edit.setMinimumHeight(30)  # Taller line edit
            value_edit.setFont(QFont("Courier New", 10))  # Monospaced font
        
        layout.addWidget(value_edit)
        
        # Add buttons
        button_layout = QHBoxLayout()
        cancel_btn = QPushButton("Cancel")
        cancel_btn.setMinimumWidth(100)
        cancel_btn.setMinimumHeight(40)
        cancel_btn.clicked.connect(dialog.reject)
        
        save_btn = QPushButton("Save")
        save_btn.setMinimumWidth(100)
        save_btn.setMinimumHeight(40)
        save_btn.clicked.connect(dialog.accept)
        
        button_layout.addStretch()
        button_layout.addWidget(cancel_btn)
        button_layout.addWidget(save_btn)
        layout.addLayout(button_layout)
        
        dialog.setLayout(layout)
        
        # Show dialog
        if dialog.exec() == QDialog.DialogCode.Accepted:
            # Update the attribute
            if isinstance(current_value, list):
                # Multi-valued attribute - split by lines
                new_value = value_edit.toPlainText().split("\n")
                # Remove empty strings
                new_value = [v for v in new_value if v.strip()]
                if new_value:
                    self.custom_attributes[attr_name] = new_value
                else:
                    # If empty list, remove the attribute
                    if attr_name in self.custom_attributes:
                        del self.custom_attributes[attr_name]
            else:
                # Single-valued attribute
                new_value = value_edit.text().strip()
                if new_value:
                    self.custom_attributes[attr_name] = new_value
                else:
                    # If empty string, remove the attribute
                    if attr_name in self.custom_attributes:
                        del self.custom_attributes[attr_name]
            
            # Update the table
            if attr_name in self.custom_attributes:
                value = self.custom_attributes[attr_name]
                if isinstance(value, list):
                    display_value = "\n".join(str(v) for v in value)
                else:
                    display_value = str(value)
                    
                self.attributes_table.item(row, 1).setText(display_value)
            else:
                self.attributes_table.item(row, 1).setText("")
                
    def clear_attribute(self):
        """Clear the selected attribute value"""
        selected_items = self.attributes_table.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "No Selection", "Please select an attribute to clear")
            return
        
        # Get the attribute name
        row = selected_items[0].row()
        attr_name = self.attributes_table.item(row, 0).text()
        
        # Remove the attribute from custom attributes
        if attr_name in self.custom_attributes:
            del self.custom_attributes[attr_name]
            
        # Clear the display
        self.attributes_table.item(row, 1).setText("")
    
    def get_user_schema_attributes(self):
        """
        Get common user attributes for schema
        
        Returns:
            List of attribute names
        """
        # This is a comprehensive list of common user attributes
        schema_attrs = [
            # Basic user attributes
            'sAMAccountName', 'givenName', 'sn', 'displayName', 'userPrincipalName',
            'mail', 'proxyAddresses', 'mailNickname', 'name', 'cn',
            
            # Contact information
            'telephoneNumber', 'mobile', 'ipPhone', 'homePhone', 'pager', 'facsimileTelephoneNumber',
            'otherTelephone', 'otherMobile', 'otherHomePhone', 'otherPager', 'otherFacsimileTelephoneNumber',
            'info', 'notes',
            
            # Address information
            'streetAddress', 'l', 'st', 'postalCode', 'c', 'co', 'countryCode',
            'physicalDeliveryOfficeName', 'postOfficeBox',
            
            # Job information
            'title', 'department', 'company', 'description', 'manager',
            'directReports', 'employeeID', 'employeeNumber', 'employeeType', 
            'division', 'wWWHomePage', 'url',
            
            # Account state and security
            'userAccountControl', 'accountExpires', 'pwdLastSet', 'lockoutTime',
            'badPasswordTime', 'badPwdCount', 'logonCount', 'lastLogon', 'lastLogonTimestamp',
            'userWorkstations', 'scriptPath', 'profilePath', 'homeDrive', 'homeDirectory',
            'msDS-UserPasswordExpiryTimeComputed', 'whenCreated', 'whenChanged',
            
            # Groups and other relationships
            'memberOf', 'primaryGroupID', 'distinguishedName', 'objectGUID', 
            'objectSid', 'objectCategory', 'objectClass', 'servicePrincipalName',
            
            # Additional useful attributes
            'extensionAttribute1', 'extensionAttribute2', 'extensionAttribute3', 
            'extensionAttribute4', 'extensionAttribute5', 'extensionAttribute6',
            'extensionAttribute7', 'extensionAttribute8', 'extensionAttribute9',
            'extensionAttribute10', 'extensionAttribute11', 'extensionAttribute12',
            'extensionAttribute13', 'extensionAttribute14', 'extensionAttribute15',
            
            # Exchange attributes
            'msExchHomeServerName', 'homeMDB', 'homeMTA', 'msExchUserAccountControl',
            'msExchMailboxGuid', 'msExchArchiveGUID', 'msExchArchiveName',
            'msExchPoliciesIncluded', 'msExchRecipientTypeDetails',
            'msExchVersion', 'protocolSettings', 'deliverAndRedirect',
            
            # Custom attributes
            'comment', 'adminDescription', 'adminDisplayName', 'assistant',
            'personalTitle', 'middleName', 'uid', 'initials', 'preferredLanguage',
            'generationQualifier', 'otherMailbox'
        ]
            
        # Try to get schema attributes from the server, if supported
        try:
            if self.ldap_conn and hasattr(self.ldap_conn.server, 'schema') and self.ldap_conn.server.schema:
                schema = self.ldap_conn.server.schema
                if 'user' in schema.object_classes:
                    # Add all attributes from schema
                    for attr in schema.object_classes['user'].must_contain:
                        if attr not in schema_attrs:
                            schema_attrs.append(attr)
                    for attr in schema.object_classes['user'].may_contain:
                        if attr not in schema_attrs:
                            schema_attrs.append(attr)
        except Exception:
            # If schema retrieval fails, use the predefined list
            pass
            
        return schema_attrs