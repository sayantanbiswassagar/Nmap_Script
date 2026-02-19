import nmap

scanner=nmap.PortScanner()
ip= 'target-ip'
scanner.scan(ip,'10-30')
print(f"Results for {ip}: ")
for proto in scanner[ip].all_protocols():
    ports = scanner[ip][proto].keys()
    for port in ports:
        state = scanner[ip][proto][port]['state']
        print(f"Port {port}/{proto}: {state}")

