# Network Traffic Analyzer

This project is a Python script for capturing and analyzing network traffic, focusing on DNS traffic, using the Scapy library. It provides a simple interface for monitoring network activity and extracting relevant information from captured packets.

## Features

- Captures network traffic on a specified network interface.
- Filters traffic based on user-defined criteria (e.g., port number, protocol).
- Extracts information from DNS packets, including DNS queries and answers.
- Integrates WHOIS lookup for source and destination IP addresses.
- Saves analyzed traffic data to a CSV file for further analysis.

## Requirements

- Python 3.x
- Scapy library
- python-whois library

## Installation

1. Clone the repository:

    ```sh
    git clone https://github.com/farazulhoda/network-traffic-analyzer.git
    ```

2. Install dependencies:

    ```sh
    pip install scapy python-whois
    ```

## Usage

1. Navigate to the project directory:

    ```sh
    cd network-traffic-analyzer
    ```

2. Navigate to src folder:

    ```sh
    cd src
    ```

3. Run the script:

    ```sh
    sudo python3 network_analyzer.py
    ```

4. Follow the on-screen instructions to capture and analyze network traffic.

## Contributing

Contributions are welcome! Feel free to submit bug reports, feature requests, or pull requests.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.