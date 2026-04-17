import sys
import os

# Add openvpn_monitor to the path so imports like `from util import ...` work
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'openvpn_monitor'))
