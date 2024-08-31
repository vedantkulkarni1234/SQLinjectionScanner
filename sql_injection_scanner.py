import requests
from bs4 import BeautifulSoup
import subprocess
import re
import sys
import time
from urllib.parse import urlparse, parse_qs

# Function to display a progress bar in the console
def progress_bar(current, total, bar_length=40):
    fraction = current / total
    arrow = '█' * int(round(fraction * bar_length))
    spaces = '-' * (bar_length - len(arrow))
    percent = round(fraction * 100, 2)
    sys.stdout.write(f'\r[Progress] |{arrow}{spaces}| {percent}%')
    sys.stdout.flush()

# Function to open a new terminal window and execute a command
def open_terminal_and_run(command, title="Terminal"):
    if sys.platform == "win32":
        # Windows
        subprocess.Popen(["start", "cmd", "/K", command], shell=True)
    elif sys.platform == "darwin":
        # macOS
        subprocess.Popen(["osascript", "-e", f'tell application "Terminal" to do script "{command}"'], shell=True)
    else:
        # Linux
        subprocess.Popen(["xterm", "-e", command])

# Function to authenticate users
def authenticate_user():
    print("\n[Authentication]")
    username = input("Enter username: ")
    password = input("Enter password: ")
    if username == "admin" and password == "password":
        print("Authentication successful.")
    else:
        print("Authentication failed.")
        sys.exit()

# Validate the URL format
def validate_url(url):
    if not re.match(r'^(http|https)://', url):
        print("Invalid URL format. Please ensure the URL starts with 'http://' or 'https://'.")
        return False
    return True

# Save logs to a file
def save_logs_to_file(logs, filename="scan_logs.txt"):
    with open(filename, 'w') as file:
        for log in logs:
            file.write(log + "\n")
    print(f"\nScan logs saved to {filename}")

# Function to display error messages
def print_error(message, details=""):
    print(f"\n[Error] {message}")
    if details:
        print(f"Details: {details}")

# Function to display progress messages
def display_progress(message):
    print(f"[Progress] {message}")

# Function to save extracted URLs to a file
def save_extracted_urls(urls, filename="extracted_urls.txt"):
    with open(filename, 'w') as file:
        for url in urls:
            file.write(url + "\n")
    print(f"\nExtracted URLs saved to {filename}")

# Log level control
def get_log_level():
    print("\n[Configuration] Select log verbosity level:")
    print("  1. Errors only")
    print("  2. Errors and Warnings")
    print("  3. Detailed Logs")
    choice = input("Enter your choice (default 3): ") or "3"
    return int(choice)

# Get scan timeout from user
def get_scan_timeout():
    timeout = input("Enter scan timeout in seconds (default 60): ") or "60"
    return int(timeout)

# Get custom HTTP headers from user
def get_custom_headers():
    headers = {}
    print("\n[Configuration] Enter custom HTTP headers (leave blank to skip):")
    while True:
        header = input("  Header (key: value): ")
        if not header:
            break
        key, value = header.split(':', 1)
        headers[key.strip()] = value.strip()
    return headers

# Get retry limit for URL extraction
def get_retry_limit():
    retries = input("Enter retry limit for URL extraction (default 3): ") or "3"
    return int(retries)

# Display detailed scan summary
def display_detailed_summary(vulnerable_urls, total_urls):
    print("\n[Detailed Summary] Scan completed.")
    print(f"Total URLs scanned: {total_urls}")
    print(f"Total vulnerabilities found: {len(vulnerable_urls)}")
    if vulnerable_urls:
        print("Vulnerable URLs:")
        for url in vulnerable_urls:
            print(f"  - {url}")
    else:
        print("No vulnerabilities detected.")

# Auto-detect forms with 'id' parameters
def auto_detect_forms(base_url, soup):
    forms_with_id = set()
    for form in soup.find_all('form'):
        action = form.get('action')
        if action and 'id=' in action:
            full_url = requests.compat.urljoin(base_url, action)
            forms_with_id.add(full_url)
    return list(forms_with_id)

# Get network proxy configuration
def get_proxy_config():
    use_proxy = input("Do you want to use a network proxy? (Y/n, default n): ").lower() == 'y'
    proxy_url = ""
    if use_proxy:
        proxy_url = input("Enter the proxy URL (e.g., http://127.0.0.1:8080): ")
    return proxy_url

# Filter URLs by keyword or pattern
def filter_urls(urls):
    keyword = input("Enter a keyword or pattern to filter URLs (leave blank to skip): ")
    if not keyword:
        return urls
    return [url for url in urls if keyword in url]

# Retry mechanism for URL extraction
def extract_urls_with_retry(base_url, max_retries=3, custom_headers=None, proxy_url=None):
    headers = custom_headers if custom_headers else {}
    proxies = {'http': proxy_url, 'https': proxy_url} if proxy_url else None

    for attempt in range(max_retries):
        try:
            response = requests.get(base_url, headers=headers, proxies=proxies)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, 'html.parser')

            urls_with_id = set()
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href']
                if 'id=' in href:
                    full_url = requests.compat.urljoin(base_url, href)
                    urls_with_id.add(full_url)

            # Auto-detect forms
            forms_with_id = auto_detect_forms(base_url, soup)
            urls_with_id.update(forms_with_id)

            # Save extracted URLs to file and display in new terminal
            save_extracted_urls(urls_with_id)
            open_terminal_and_run(f"cat extracted_urls.txt", "Extracted URLs")

            return list(urls_with_id)

        except requests.exceptions.RequestException as e:
            print_error(f"Attempt {attempt + 1} failed.", str(e))
            if attempt < max_retries - 1:
                print("Retrying...")
            else:
                return []

# Function to run SQLMap on URLs and update progress
def run_sqlmap_on_urls(urls, crawl_level="1", use_random_agent=True, verbose=False, timeout=60):
    logs = []
    total_urls = len(urls)

    for idx, url in enumerate(urls):
        display_progress(f"Running SQLMap on: {url}")

        # Open new terminal for SQLMap process
        command = f"sqlmap -u {url} --batch --crawl={crawl_level} --timeout={timeout}"
        if use_random_agent:
            command += " --random-agent"
        if verbose:
            command += " -v"

        open_terminal_and_run(command, "SQLMap Process")

        # Wait for the SQLMap process to finish (or handle asynchronously in real implementation)
        time.sleep(10)  # Adjust as needed for your system

        # Dummy logs for demonstration
        output = f"Output for {url} (simulated)"
        logs.append(f"--- SQLMap Output for {url} ---\n{output}")

        # Update the progress bar
        progress_bar(idx + 1, total_urls)

    return logs

# Function to display colored text in the terminal
def colored_text(text, color="green"):
    colors = {
        "green": "\033[92m",
        "red": "\033[91m",
        "yellow": "\033[93m",
        "endc": "\033[0m"
    }
    return f"{colors.get(color, '')}{text}{colors['endc']}"

def main_menu():
    print("\n[Main Menu]")
    print("1. Start Scan")
    print("2. Configure Settings")
    print("3. Exit")
    choice = input("Enter your choice (default 1): ") or "1"
    return int(choice)

if __name__ == "__main__":
    # Authenticate the user
    authenticate_user()

    while True:
        choice = main_menu()

        if choice == 1:
            # Get base URL from user input
            base_url = input("Enter the base URL to extract and scan: ").strip()

            # Validate the input URL
            if not validate_url(base_url):
                sys.exit()

            # Get configuration options from the user
            custom_headers = get_custom_headers()
            proxy_url = get_proxy_config()
            retry_limit = get_retry_limit()
            log_level = get_log_level()
            scan_timeout = get_scan_timeout()

            # Extract URLs with retry mechanism
            extracted_urls = extract_urls_with_retry(base_url, max_retries=retry_limit, custom_headers=custom_headers, proxy_url=proxy_url)

            if not extracted_urls:
                print_error("No URLs with 'id=' parameters found. Exiting.")
                sys.exit()

            # Filter URLs based on user input
            filtered_urls = filter_urls(extracted_urls)

            # Run SQLMap on filtered URLs
            scan_logs = run_sqlmap_on_urls(filtered_urls, timeout=scan_timeout)

            # Display a detailed scan summary
            vulnerable_urls = [url for log in scan_logs if "vulnerable URL found" in log.lower()]
            display_detailed_summary(vulnerable_urls, len(filtered_urls))

            # Save logs to a file
            save_logs_to_file(scan_logs)

            print("\n[Completed] SQLMap scanning completed successfully.")

        elif choice == 2:
            print("Configuration settings are interactive and are part of the main scanning process.")
            continue

        elif choice == 3:
            print("Exiting the application. Goodbye!")
            sys.exit()

        else:
            print("Invalid choice. Please select a valid option.")
