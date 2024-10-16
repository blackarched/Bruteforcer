# Bruteforcer

Brute Force Attack Tool - README
Description:
This is a fully functional, highly customizable, and automated brute force attack tool designed to be both user-friendly and versatile. By leveraging Python’s multi-threading, smart password guessing techniques, and real-time monitoring, this tool is built for both web login brute-forcing and other advanced attack vectors like Bitcoin wallet brute-forcing and IP/website scanning.

The tool comes with advanced features such as customizable response patterns, CAPTCHA detection, session persistence, request pacing to mimic human behavior, and detailed reporting. With a modular architecture, it can easily be extended to support new attack vectors or adapted to various login mechanisms, including OAuth and multi-step authentication.

Features:
Thread Pooling with ThreadPoolExecutor:

Efficient thread management for parallel brute-force attacks using Python’s concurrent.futures.ThreadPoolExecutor.
Customizable Response Patterns:

You can specify the keywords or HTTP status codes that define success or failure during brute force attempts. This is useful when different systems have varying response formats.
Captcha Detection:

The tool can detect rate-limiting responses like HTTP 429 or HTML elements related to CAPTCHA, helping avoid useless brute-force attempts.
Smart Password Guessing:

The password guessing mechanism is dictionary-based and can adapt to common patterns such as adding numbers, capitalizing the first letter, or appending popular suffixes like 123, 2023, etc.
Username-Password Relationship:

Implements common username-password combinations like username123 or username + current year to increase the chances of success.
Detailed Reports:

Each attempt is logged with details like the time of the attempt, IP address used, username-password combination, and the HTTP response. Reports can be exported to both CSV and JSON formats.
Real-Time Monitoring:

Track metrics such as attempts per second, success rates, and failures live, allowing you to monitor the tool’s performance in real-time.
Request Pacing:

Randomized delays between requests are added to simulate human-like behavior, preventing the tool from being easily detected by rate-limiting algorithms.
Session Persistence:

The tool maintains session cookies between requests to reduce the likelihood of triggering login mechanisms that reset sessions after failed attempts.
Modular Design:

Easily extend the tool by adding new attack vectors or adjusting it for different login mechanisms (e.g., OAuth, multi-step logins).
Multiple Functionalities:
Web login brute forcing
Bitcoin wallet brute forcing
IP/website port scanning
DDoS simulation
Admin panel discovery tool
How to Use:
1. Installation:

Make sure you have Python installed on your system.
Install the required Python dependencies by running:
Copy code
pip install -r requirements.txt
The necessary libraries include:
requests
concurrent.futures
colorama
pyfiglet
tqdm
2. Running the Tool:

Run the tool by executing the following command in your terminal:
Copy code
python bruteforcer.py
3. Main Menu:

Upon running, you will be presented with the following menu options:
Web Login Brute Force
Bitcoin Brute Force (Wallet Balance Check)
Admin Panel Discovery Tool
IP/Website Scanner
DDoS Attack Simulation
Exit
4. Web Login Brute Force:

Select option 1 to initiate a web login brute-force attack.
The tool will ask for:
Target URL: The URL of the login page.
Username: The username to attack.
Password List: Path to the password list file.
Optionally, specify the success or failure keywords that indicate if an attempt was successful or failed.
The tool will then use the provided username and passwords to attempt login via brute force.
5. Bitcoin Brute Force:

Select option 2 to initiate a Bitcoin wallet brute force. This will continuously generate private keys and corresponding public keys until it finds a wallet with a balance.
6. IP/Website Scanner:

Select option 4 to scan for open ports on a specified IP or website. The tool will attempt to resolve the domain/IP and scan for common open ports like 80, 443, 22, etc.
7. DDoS Simulation:

Select option 5 to simulate a DDoS attack on a given IP address and port.
You need to provide the target IP, port, and your IP address. The tool will simulate the attack by sending large amounts of UDP packets.
8. Admin Panel Discovery:

Select option 3 to scan a target URL for potential admin panel pages.
9. Logging & Reporting:

All brute-force attempts are logged in a CSV file named bruteforce_report.csv and optionally in a JSON file for further analysis.
Future Enhancements:
OAuth and Multi-Step Login Support:

Expand the tool to handle more complex login systems like OAuth and multi-step authentication processes.
Custom Dictionary Enhancements:

Allow users to input their own password patterns and rules for smarter guessing.
Graphical User Interface (GUI):

Add a GUI for better user interaction, making it easier to monitor real-time data and input configurations.
Rate-Limit Detection and Bypass:

Implement advanced methods to detect and bypass rate-limiting algorithms more effectively.
Cloud-Based Distribution:

Allow distributed brute-force attacks using multiple cloud servers for enhanced performance and scalability.
This tool is for educational and penetration testing purposes only. Use it responsibly and only on systems you have explicit permission to test. Unauthorized use is illegal and unethical.



