"""
User template management for Active Directory user creation.
"""

import os
import json
from pathlib import Path


class UserTemplate:
    """Class to store user template settings"""
    def __init__(self, name, settings):
        """
        Initialize a user template
        
        Args:
            name: Template name
            settings: Dictionary of settings
        """
        self.name = name  # Template name
        self.settings = settings  # Dictionary of settings
        
    def to_dict(self):
        """
        Convert template to dictionary for serialization
        
        Returns:
            Dictionary representation of the template
        """
        return {
            "name": self.name,
            "settings": self.settings
        }
    
    @classmethod
    def from_dict(cls, data):
        """
        Create a template from a dictionary
        
        Args:
            data: Dictionary containing template data
            
        Returns:
            New UserTemplate instance
        """
        return cls(data["name"], data["settings"])


class TemplateManager:
    """Class to manage user templates"""
    def __init__(self, file_path=None):
        """
        Initialize the template manager
        
        Args:
            file_path: Path to template storage file (optional)
        """
        if file_path is None:
            # Store templates in user's home directory
            home_dir = str(Path.home())
            self.file_path = os.path.join(home_dir, "ad_user_templates.json")
        else:
            self.file_path = file_path
        self.templates = self.load_templates()
        
    def load_templates(self):
        """
        Load templates from file
        
        Returns:
            Dictionary of templates {name: UserTemplate}
        """
        try:
            with open(self.file_path, 'r') as f:
                data = json.load(f)
                return {name: UserTemplate.from_dict(template) 
                        for name, template in data.items()}
        except (FileNotFoundError, json.JSONDecodeError):
            return {}
            
    def save_templates(self):
        """Save templates to file"""
        data = {name: template.to_dict() 
                for name, template in self.templates.items()}
        with open(self.file_path, 'w') as f:
            json.dump(data, f, indent=4)
            
    def add_template(self, template):
        """
        Add a template to the collection
        
        Args:
            template: UserTemplate instance
        """
        self.templates[template.name] = template
        self.save_templates()
        
    def get_template(self, name):
        """
        Get a specific template by name
        
        Args:
            name: Template name
            
        Returns:
            UserTemplate instance or None if not found
        """
        return self.templates.get(name)
        
    def get_template_names(self):
        """
        Get list of template names
        
        Returns:
            List of template names
        """
        return list(self.templates.keys())
        
    def delete_template(self, name):
        """
        Delete a template by name
        
        Args:
            name: Template name
            
        Returns:
            True if deletion successful, False otherwise
        """
        if name in self.templates:
            del self.templates[name]
            self.save_templates()
            return True
        return False
    
    def export_templates(self, file_path):
        """
        Export templates to a JSON file
        
        Args:
            file_path: Path to export file
        """
        data = {name: template.to_dict() 
                for name, template in self.templates.items()}
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=4)
    
    def import_templates(self, file_path):
        """
        Import templates from a JSON file
        
        Args:
            file_path: Path to import file
            
        Returns:
            Number of templates imported
            
        Raises:
            Exception if import fails
        """
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
                imported = 0
                for name, template_data in data.items():
                    self.templates[name] = UserTemplate.from_dict(template_data)
                    imported += 1
                self.save_templates()
                return imported
        except (FileNotFoundError, json.JSONDecodeError, KeyError) as e:
            raise Exception(f"Error importing templates: {str(e)}")