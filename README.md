# Palo Alto Security and NAT Policy Optimization Tool
## Overview
This tool automates the Policy Optimizer functionality within Panorama or PAN-OS.
Specifically it performs the following tasks:
1. Collects hit data from the firewalls.
2. If a rule has not been hit within a specified number of days, it will be tagged and deleted.
3. If a rule was disabled and tagged more than a specified number of days ago, the rule will be deleted.
These functions can be run on the rules in a single device group, or across the entire Panorama deployment.

## Modes of Operation
This tool has 3 different modes of operation:
1. **Active mode** - This is the default mode, and will perform configuration changes in Panorama.
2. **Report mode** - This mode will walk through the same logic as Active mode, but instead of making changes to Panorama, it will only log changes that *would* have been made if it was run in active mode.
3. **Clean mode** - This mode will find all changes made by the script at any point and revert them. It will identify affected rules by tag, and perform the following:
   1. Remove the tag
   2. Enable the rule if necessary

Each mode has its own log file, specified in the main policy-optimizer.py file.

## Set up
This script was tested on Python 3.11, but should work with most versions of Python 3. Once Python is installed, environment variables (USERNAME and PASSWORD) will need to be created with administrative credentials in Panorama. It is recommended that a specific service account is created for this that does not have permission to log into the GUI or access the CLI, but has permission to make changes with the API.

Any scheduling tool that can be used to run a Python script can be used to run this script. This script is not set up to run itself.

## Requirements
- Python 3
- The only 3rd party library that needs to be installed is the PAN-OS Python SDK
```
pip install pan-os-python
```