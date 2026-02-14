import ipaddress
import socket
import threading
from concurrent.futures import ThreadPoolExecutor
import argparse
import sys
import json

def create_connection(host, port):

    #Create socket object 
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(1)

    try:
        # Send TCP request
        result = sock.connect_ex((host, port))
        if result == 0:
            banner = sock.recv(1024)
            decoded_banner = None
            if banner:
                decoded_banner = banner.decode('utf-8', errors='ignore').strip()

            return {"status": "OPEN", "banner": decoded_banner}
        else:
            return {"status": "CLOSED", "banner": None}
    except socket.error:
        return {"status": "ERROR", "banner": None}
    finally:
        sock.close()

def socket_threaded(ip, port, lock, results):
    connect = create_connection(str(ip), port)

    if connect["status"] == "OPEN":
        banner = connect["banner"]

        with lock:
            if ip in results:
                results[ip].append((port, banner))
            else:
                results[ip] = [(port, banner)]

def display_results(results):
    if not results:
        print("No active hosts or open ports found on the target network.")
        return 
    
    for ip, ports in sorted(results.items()):
        total_hosts = len(results)

        print(f"\n{ip}:")
        for port, banner in ports:
            if banner:
                print(f"  Port: {port} - Banner: {banner}")
            else:
                print(f"  Port: {port} - Open (No banner)")
    print(f"\nScan complete - Found {total_hosts} host(s)")

    print()

def save_to_json(results, filename):
    output = {}

    for ip, ports in results.items():
        output[str(ip)] = [{"port": port, "banner": banner} for port, banner in ports]

    with open(filename, 'w') as f:
        json.dump(output, f, indent=4)
    
    print(f"\nResults saved to {filename}")

def main():
    
    try:
        # Create CLI flags
        parser = argparse.ArgumentParser(description='Multi-threaded network port scanner with banner grabbing)')
        parser.add_argument('-t', '--target', required=True, help='Target network (CIDR notation, e.g., 192.168.1.0/24)')
        parser.add_argument('-p', '--ports', default='22,80,443', help='Ports to scan (comma separated, default: 22,80,443)')
        parser.add_argument('-w', '--workers', type=int, default=100, help='Max concurrent workers (default 100))')
        parser.add_argument('-o', '--output', help='Output file (JSON format)')

        args = parser.parse_args()
        
        # Validate network
        try:
            addr = ipaddress.ip_network(args.target, strict=False)
        except ValueError as e:
            print(f"Error: {args.target} does not appear to be a valid IPV4 or IPV6 network")
            sys.exit(1)
       
        # Validate ports
        try:
            common_ports = [int(p) for p in args.ports.split(',')]
        except ValueError:
            print(f"Error: {args.ports} does not appear to be a valid port number")
            sys.exit(1) 

        invalid_ports = [p for p in common_ports if p < 1 or p > 65535]
        if invalid_ports:
            print(f"Error: Invalid port(s): {invalid_ports}")
            sys.exit(1) 
        
        # Setup
        results = {}
        lock = threading.Lock()
        
        print(f"Starting scan on {addr}")
        
        max_workers = args.workers

        # Thread pool executor
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            for ip in addr.hosts():
                for port in common_ports:
                    executor.submit(socket_threaded, ip, port, lock, results)
        
        # Print results
        display_results(results)
  
        # Save to json if requested
        if args.output:
            save_to_json(results, args.output)


    except KeyboardInterrupt:
        print("Shutting down...")
        sys.exit(0)
    
if __name__ == "__main__":
    main()
