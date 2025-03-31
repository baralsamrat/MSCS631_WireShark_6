#!/bin/bash
# run_lab6.sh
# This script automates the execution of lab6.py.
# It sets up a Python virtual environment, installs required packages,
# and then runs lab6.py. It also handles checking for and downloading the 
# required pcap file if not present.

SCRIPT="lab6.py"
PCAP_FILE="tls-wireshark-trace1.pcapng"
ZIP_URL="http://gaia.cs.umass.edu/wireshark-labs/wireshark-traces-8.1.zip"
ZIP_FILE="wireshark-traces-8.1.zip"

# Create virtual environment if not already present.
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate the virtual environment.
echo "Activating virtual environment..."
# Use different paths for Windows vs Unix-like systems.
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    source venv/Scripts/activate
else
    source venv/bin/activate
fi

# Upgrade pip and install required packages.
echo "Installing required packages..."
pip install --upgrade pip
pip install pyshark requests

# Run lab6.py in offline mode.
# The script itself will check for the PCAP file and prompt for download if needed.
echo "Running lab6.py in offline mode..."
python $SCRIPT --mode offline

# Deactivate the virtual environment.
echo "Deactivating virtual environment..."
deactivate 2>/dev/null || echo "Deactivation not available; please close the terminal if needed."

echo "Automation complete."
