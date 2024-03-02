#!/bin/bash

# Set the network interface to capture traffic from
INTERFACE="eth0"

# Set the filter expression to capture specific traffic (optional)
FILTER="tcp port 80"

# Set the output file for capturing packets
OUTPUT_FILE="captured_traffic.pcap"

# Start capturing network traffic using tcpdump
echo "Capturing network traffic on interface $INTERFACE..."
sudo tcpdump -i $INTERFACE -w $OUTPUT_FILE $FILTER &

# Get the PID of the tcpdump process
TCPDUMP_PID=$!

# Monitor the traffic capture process
sleep 5
if ps -p $TCPDUMP_PID > /dev/null; then
    echo "Network traffic capture is running..."
else
    echo "Failed to start network traffic capture."
    exit 1
fi

# Wait for a specified duration (e.g., 30 seconds)
echo "Capturing network traffic for 30 seconds..."
sleep 30

# Stop tcpdump process
echo "Stopping network traffic capture..."
sudo kill $TCPDUMP_PID

# Analyze captured traffic using tshark
echo "Analyzing captured traffic..."
tshark -r $OUTPUT_FILE -T fields -e frame.number -e ip.src -e ip.dst -e tcp.srcport -e tcp.dstport -e udp.srcport -e udp.dstport -e http.host -e http.request.uri -e dns.qry.name -e dns.a -e ssl.handshake.extensions_server_name -E header=y -E separator=';' > analyzed_traffic.csv

# Display the analyzed traffic
echo "Analyzed traffic saved in analyzed_traffic.csv:"
cat analyzed_traffic.csv

# Clean up - remove the captured traffic file
rm $OUTPUT_FILE