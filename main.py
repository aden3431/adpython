#!/usr/bin/env python3
"""
Active Directory Management Tool
Main entry point for the application
"""
import sys
import os

# Add the current directory to the Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from PyQt6.QtWidgets import QApplication
from Login import LoginWindow
from helpers import get_app_stylesheet

class MainApplication:
    """Main application class"""
    def __init__(self):
        """Initialize the application"""
        self.app = QApplication(sys.argv)
        self.app.setStyleSheet(get_app_stylesheet())
        self.login_window = None
        
    def run(self):
        """Run the application"""
        self.login_window = LoginWindow()
        self.login_window.show()
        return self.app.exec()

def main():
    """Main function"""
    app = MainApplication()
    sys.exit(app.run())

if __name__ == "__main__":
    main()