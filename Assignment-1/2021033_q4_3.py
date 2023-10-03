import nmap

target_network = "142.250.192.196" # Google IPv4  address

def scan_ports_in_chunks(nm, host):
    port_ranges = [(1, 1023), (1024, 49151), (49152, 65535)]
    # port_ranges = [(1, 1023)]
    scan_args = "-T4 -sT -n"  

    for start_port, end_port in port_ranges:
        print(f"Scanning ports {start_port}-{end_port} on host {host}")
        nm.scan(hosts=host, arguments=f"{scan_args} -p {start_port}-{end_port}")
        
        open_ports = nm[host].get('tcp', {}).keys()
        if open_ports:
            print(f"Open ports in range {start_port}-{end_port} on {host}: {list(open_ports)}")
            check_vulnerabilities(nm, host)
        else:
            print(f"No open ports found in range {start_port}-{end_port} on {host}")

def scan_network(target_network):
    nm = nmap.PortScanner()
    
    nm.scan(hosts=target_network, arguments="-sn -n") 
    
    for host in nm.all_hosts():
        print(f"Scanning host: {host}")
        scan_ports_in_chunks(nm, host)

        open_ports = nm[host].get('tcp', {}).keys()
        if open_ports:
            print(f"Open ports on {host}: {list(open_ports)}")
        else:
            print(f"No open ports found on {host}")

def check_vulnerabilities(nm, host):
    for port in nm[host]['tcp'].keys():
        result = nm.scan(hosts=host, ports=str(port), arguments="--script vuln")
        if 'script' in result['scan'][host]['tcp'][port]:
            vulnerabilities = result['scan'][host]['tcp'][port]['script']['vuln']
            if vulnerabilities:
                print(f"Vulnerabilities on {host}:{port}:")
                for vulnerability in vulnerabilities:
                    print(f"- {vulnerability}")

try:
    scan_network(target_network)
except Exception as e:
    print(f"An error occurred: {e}")
