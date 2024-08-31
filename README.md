---

# SQL Injection Scanner Tool

## Overview

This command-line interface (CLI) tool scans a provided website URL for URLs containing 'id' parameters and performs SQL injection vulnerability testing using SQLMap. The tool is designed to be user-friendly and provides detailed progress updates and logging capabilities.

## Features

- **Terminal Integration**: Opens new terminal windows for URL extraction and SQLMap process.
- **Progress Bar**: Displays progress as a bar indicating the completion percentage.
- **Retry Mechanism**: Allows retrying URL extraction upon failure.
- **Custom Headers**: Users can specify custom HTTP headers.
- **Network Proxy Support**: Configure network proxy for requests.
- **Log Level Control**: Set verbosity levels for logging.
- **Scan Timeout**: Define a timeout for SQLMap scans.
- **URL Filtering**: Filter URLs based on user-defined criteria.
- **Detailed Error Messages**: Enhanced error reporting with specific details.
- **Detailed Summary**: Provides a detailed scan summary and saves logs to a file.

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/vedantkulkarni1234/SQLinjectionScanner.git
   cd SQLinjectionScanner
   ```

2. **Install Dependencies**:
   Ensure you have Python 3 installed. Then, install the required Python libraries:
   ```bash
   pip install requests beautifulsoup4
   ```

3. **Install SQLMap**:
   Download and install SQLMap from the official website or repository:
   ```bash
   git clone 
   ```

   Ensure `sqlmap.py` is in your system's PATH or adjust the command paths accordingly.

## Usage

1. **Run the Tool**:
   Execute the tool from the command line:
   ```bash
   python sql_injection_scanner.py
   ```

2. **Follow the Prompts**:
   - Enter your username and password to authenticate.
   - username - admin
   - password - password 
   - Enter the base URL you want to scan.
   - Configure settings such as custom headers, network proxy, retry limit, log level, and scan timeout.

3. **Monitor Progress**:
   - A new terminal window will open to display extracted URLs.
   - Another terminal window will open to show SQLMap execution progress.
   - The CLI will display a progress bar for SQLMap scans and detailed logs upon completion.

4. **Review Results**:
   - The extracted URLs and SQLMap scan logs will be saved to `extracted_urls.txt` and `scan_logs.txt`, respectively.
   - A detailed summary of vulnerabilities found will be displayed in the CLI.

## Configuration

### Custom Headers
Add custom HTTP headers by specifying them when prompted during the setup.

### Network Proxy
Enter a proxy URL if you need to route requests through a network proxy.

### Retry Limit
Define the number of retries for URL extraction in case of failure.

### Log Level
Choose the verbosity level for logs to control the amount of detail reported.

### Scan Timeout
Set the timeout duration for each SQLMap scan.

## Troubleshooting

- **Invalid URL Format**: Ensure the URL starts with 'http://' or 'https://'.
- **Authentication Issues**: Verify the username and password entered.
- **SQLMap Not Found**: Make sure SQLMap is installed and accessible in your system's PATH.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Feel free to adjust the repository URL, license information, and other specific details according to your project's needs.
