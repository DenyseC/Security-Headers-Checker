# Security-Headers-Checker

Title: Security Headers Checker

Description:
The Security Headers Checker is a Python script designed to automate the process of checking the security headers of a website. Security headers play a crucial role in enhancing the security posture of web applications by providing additional layers of protection against common security vulnerabilities. This script sends a GET request to the specified URL, retrieves the response headers, and checks if the expected security headers are present and configured correctly according to predefined values.

Key Features:
- Automates the process of checking security headers for a given website.
- Validates the presence and configuration of common security headers.
- Provides clear results indicating the status of each security header check.

Usage:
1. Install Python if not already installed on your system.
2. Install the `requests` library by running `pip install requests` in your terminal.
3. Clone the repository and navigate to the directory containing the script.
4. Run the script (`python security_headers_check.py`) and enter the URL of the website to check when prompted.
5. View the results of the security headers check, indicating whether each expected header is present and configured correctly.

Contributions:
Contributions to this project are welcome! If you encounter any issues, have suggestions for improvements, or want to add new features, please feel free to create a pull request.

License:
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Happy security header checking! 🛡️


```
import requests

def check_security_headers(url):
    try:
        # Send a GET request to the URL
        response = requests.get(url)

        # Extract security headers from the response
        headers = response.headers

        # Define a dictionary of expected security headers
        expected_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains; preload",
            "Referrer-Policy": "no-referrer-when-downgrade",
            "Feature-Policy": "accelerometer 'none'; camera 'none'; geolocation 'none'; gyroscope 'none'; magnetometer 'none'; microphone 'none'; payment 'none'; usb 'none'"
        }

        # Check if each expected header is present and configured correctly
        results = {}
        for header, value in expected_headers.items():
            if header in headers:
                if headers[header] == value:
                    results[header] = "PASS"
                else:
                    results[header] = "FAIL: Incorrect value"
            else:
                results[header] = "FAIL: Header not found"

        return results

    except Exception as e:
        return {"Error": str(e)}

if __name__ == "__main__":
    url = input("Enter the URL of the website to check security headers: ")
    results = check_security_headers(url)
    print("\nSecurity Headers Check Results:")
    for header, status in results.items():
        print(f"{header}: {status}") ```

