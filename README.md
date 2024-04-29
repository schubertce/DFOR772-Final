
# AWS CloudTrail Log Parser for Autopsy

## Description
The AWS CloudTrail Log Parser is an ingest module for Autopsy that allows forensic analysts to parse and analyze AWS CloudTrail log files directly within the Autopsy forensic platform. This module extracts key information from CloudTrail logs, such as event names, timestamps, source IP addresses, user agent details, and more, to aid in digital forensic investigations.

## Features
- **Log Identification**: Automatically identifies and processes AWS CloudTrail JSON log files.
- **Data Extraction**: Extracts crucial information from each log entry, including:
  - Event time
  - Event name
  - Event type
  - User identity (username, ARN, account ID)
  - User agent
  - Source IP address
  - AWS region
  - Request parameters
- **Artifact Generation**: Generates forensic artifacts for each log entry, which can be reviewed and analyzed in Autopsy.

## Installation

1. **Download the Module**:
   - Download the `AWS_CloudTrail_Log_Parser.py` file from the provided link or repository.

2. **Install the Module in Autopsy**:
   - Open Autopsy and go to `Tools` > `Python Plugins`.
   - Click on `Install` and select the downloaded `AWS_CloudTrail_Log_Parser.py` file.
   - Restart Autopsy to activate the module.

## Usage
After installation, the AWS CloudTrail Log Parser will automatically process any AWS CloudTrail log files encountered during a case investigation. To view the results:
1. Open your case in Autopsy.
2. Navigate to the `Data Sources` section.
3. Look for artifacts labeled as `CloudTrail Log Entries`, which contain the parsed log data.

## Configuration
No additional configuration is required. The module automatically detects and processes all `.json` files that match the CloudTrail log format.

## Dependencies
- Autopsy Forensic Browser (version 4.15.0 or newer recommended)
- Python scripting module enabled in Autopsy

## Troubleshooting
If you encounter issues with the module, ensure that:
- Autopsy is updated to the latest version.
- Python scripting is enabled in Autopsy.
- The module file is not corrupted and is correctly installed.

For more specific issues, consult the Autopsy forums or file an issue on the repository where this module is hosted.


