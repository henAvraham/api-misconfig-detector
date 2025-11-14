 API Misconfiguration Detector
A simple Python script that checks an API endpoint for common security misconfigurations.
📌 What this project does
This script performs a set of basic security tests on any API URL and helps identify issues such as:
Missing authentication / open access
Error leakage (stack traces, verbose server errors)
Path traversal behavior
Unsafe or unexpected HTTP method responses
Goal:
To understand how servers respond to different requests and to detect simple misconfigurations in a clear and practical way.
🧰 Tools & Technologies
Python 3
Requests library
Basic HTTP & API security concepts
▶️ How to Run
Install dependencies:
pip install -r requirements.txt
Run the script with your target URL:
python api_misconfig_detector.py https://example.com
The output will show:
Whether the API is open without authentication
If it leaks internal error messages
How it reacts to path traversal attempts
Allowed or unsafe HTTP methods
📂 Project Structure
api_misconfig_detector.py   # Main script containing all tests
requirements.txt            # Dependencies
