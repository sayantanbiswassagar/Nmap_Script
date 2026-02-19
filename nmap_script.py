#!/usr/bin/env python3

# python-nmap wrapper around the nmap binary
import nmap
import sys

# -------- Arguments --------
# We expect exactly ONE argument: the target (IP, hostname, localhost, etc)
if len(sys.argv) != 2:
    print("Usage: python3 main.py <ip/host>")
    sys.exit()

# Target provided by the user from the command line
target = sys.argv[1]


# -------- Ports --------
# Common "top ports" used in reconnaissance scans
# Faster than scanning all 65535 ports but still very informative
ports = [
"20","21","22","23","25","53","67","68","69",
"80","88","110","111","119","123","135","137","138","139",
"143","161","179","194","389","427","443","445","465","500",
"512","513","514","515","520","548","554","587","623","631",
"636","989","990","993","995","1433","1434","1521","1723",
"2049","2082","2083","2086","2087","2181","2222","2375","2376",
"2483","2484","3000","3128","3260","3306","3389","3690",
"4444","5000","5001","5060","5061","5432","5601","5800","5900",
"5985","5986","6379","6443","6667","7001","7002","7443","7777",
"8000","8008","8009","8080","8081","8082","8088","8090","8091",
"8181","8333","8443","8500","8888","9000","9042","9080","9090",
"9091","9100","9200","9443","9999","10000","11211","27017"
]

# nmap expects ports as a comma separated string: "22,80,443"
port_string = ",".join(ports)


# -------- Scan --------
print(f"\nScanning {target}...\n")

# Create scanner object (this calls the real nmap program)
scanner = nmap.PortScanner()

try:
    # -sT : TCP connect scan (works without root)
    # -sC : run default nmap scripts
    # -sV : detect service version
    # -T4 : faster timing template
    scanner.scan(target, port_string, arguments='-sT -sC -sV -T4')

except Exception as e:
    # Happens if nmap not installed, invalid host, or permissions issue
    print("Scan failed:", e)
    print("Tip: try running with sudo")
    sys.exit()


# -------- Results --------
# Flag to know if we found any open ports
found = False

# Nmap may resolve hostnames → always use what nmap actually returned
for host in scanner.all_hosts():
    print(f"Host: {host}")
    print("-" * 40)

    # Example: tcp, udp
    for proto in scanner[host].all_protocols():

        # Sort ports numerically for nicer output
        for port in sorted(scanner[host][proto].keys()):

            data = scanner[host][proto][port]

            # Ignore closed / filtered ports
            if data['state'] != "open":
                continue

            found = True

            # Extract service information safely
            name = data['name']                 # service name (http, ssh, smb)
            product = data.get('product', '')   # software (Apache, OpenSSH)
            version = data.get('version', '')   # version number

            print(f"{port}/{proto:<5} open  {name:<10} {product} {version}")

# If nothing open was discovered
if not found:
    print("No open ports found.")

print()
