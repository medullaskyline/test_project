"""This file is loaded when starting a new application instance."""
import sys
import os

# add `lib` subdirectory to `sys.path`, so our `main` module can load
# third-party libraries.
sys.path.insert(1, os.path.join(os.path.dirname(__file__), 'lib'))
sys.path.append(os.path.join(os.getcwd(), "django.zip"))
os.environ['DJANGO_SETTINGS_MODULE'] = 'test_project.settings'