import sys
import os

# Add the packages to Python path
current_dir = os.path.dirname(os.path.abspath(__file__))
packages_path = os.path.join(current_dir, '.python_packages')
sys.path.insert(0, packages_path)

# Now import your dependencies
from flask import Flask
import requests

# Your existing code
URI = "{}{}{}{}{}".format(HTTPS, WORKSPACE_ID, AZURE_URL, RESOURCE, AZURE_API_VERSION)
# ... rest of your code ...