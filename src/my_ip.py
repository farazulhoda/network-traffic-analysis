import socket

def get_ip():
    try:
        # Create a socket object to get the IP address
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_address = s.getsockname()[0]
        s.close()
        return ip_address
    except Exception as e:
        return f"Error: {str(e)}"

if __name__ == "__main__":
    ip_address = get_ip()
    print("Your IP address is:", ip_address)