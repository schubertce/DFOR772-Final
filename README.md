
# AWS CloudTrail Log Parser for Autopsy

## Description
The AWS CloudTrail Log Parser is an ingest module for Autopsy that allows forensic analysts to parse and analyze AWS CloudTrail log files directly within the Autopsy forensic platform. This module extracts key information from CloudTrail logs, such as event names, timestamps, source IP addresses, user agent details, and more, to aid in digital forensic investigations.

This tool was developed as a final exam project for a graduate course (DFOR772-Forensic Artifact Extraction) for the Digital Forensics program at George Mason University under the supervision of Dr. Eric Eppley.

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
   - This will open an explorer window to the location of the Autopsy Python Plugin repository.
   - Create a new folder and copy the `AWS_CloudTrail_Log_Parser.py` file into the new folder.
   - The module should now be available 

## Usage
After installation, the AWS CloudTrail Log Parser will automatically process any AWS CloudTrail log files encountered during Data Source ingestion if the module is selected. Alternatively, you can click on `Tools`, then click `Run Ingest Module`, and then select which Data Source you would like to run it on. You will now be presented with a list of modules. Select the one you wish to run and click `Finish`.

To view the results:
1. Open your case in Autopsy.
2. Navigate to the `Data Artifacts` section.
3. Look for artifacts labeled as `CloudTrail Log Entries`, which contain the parsed log data.

## Configuration
No additional configuration is required. The module automatically detects and processes all `.json` files that match the CloudTrail log naming format.

## Dependencies
- Autopsy Forensic Browser (version 4.15.0 or newer recommended)
- Python scripting module enabled in Autopsy

## Troubleshooting
If you encounter issues with the module, ensure that:
- Autopsy is updated to the latest version.
- Python scripting is enabled in Autopsy.
- The module file is not corrupted and is correctly installed.

For more specific issues, consult the Autopsy forums or file an issue on the repository where this module is hosted.


