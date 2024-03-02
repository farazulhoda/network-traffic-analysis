# network-traffic-analysis
Network traffic analysis across various application and network layers. Helps to capture network traffic using tcpdump, filters the captured packets with tshark, and extracts information about different protocol layers using tshark and awk.


## This script performs the following steps:

- Captures network traffic using tcpdump on the specified interface ($INTERFACE) and applies an optional filter expression ($FILTER).

- Monitors the capture process and ensures that tcpdump is running.

- Captures traffic for a specified duration (e.g., 30 seconds).

- Stops the tcpdump process.

- Analyzes the captured traffic using tshark and extracts information about various protocol layers such as IP addresses, ports, HTTP host, HTTP request URI, DNS queries, and SSL/TLS server names.

- Saves the analyzed traffic information in a CSV file (analyzed_traffic.csv).

- Displays the analyzed traffic on the console.

- Cleans up by removing the captured traffic file ($OUTPUT_FILE).

### HOW TO RUN?

- Remember to run this script with appropriate permissions (e.g., using sudo) since capturing network traffic typically requires administrative privileges.

- Ensure that tcpdump and tshark are installed on your system before running the script.