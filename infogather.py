import socket
import whois
import dns.resolver
import requests
import subprocess

# Get IP address from a domain name
def get_ip_address(domain):
    try:
        ip_address = socket.gethostbyname(domain)
        return ip_address
    except socket.gaierror:
        return None

# Get WHOIS information
def get_whois_info(domain):
    try:
        domain_info = whois.whois(domain)
        return domain_info
    except Exception as e:
        return str(e)

# Get DNS records (A, MX, NS)
def get_dns_records(domain):
    records = {}
    try:
        # A record
        a_record = dns.resolver.resolve(domain, 'A')
        records['A'] = [ip.to_text() for ip in a_record]
    except Exception as e:
        records['A'] = str(e)
    
    try:
        # MX record
        mx_record = dns.resolver.resolve(domain, 'MX')
        records['MX'] = [mx.to_text() for mx in mx_record]
    except Exception as e:
        records['MX'] = str(e)

    try:
        # NS record
        ns_record = dns.resolver.resolve(domain, 'NS')
        records['NS'] = [ns.to_text() for ns in ns_record]
    except Exception as e:
        records['NS'] = str(e)

    return records

# Scan open ports using nmap
def scan_open_ports(ip):
    try:
        # Call nmap via subprocess
        result = subprocess.check_output(['nmap', '-p-', ip], universal_newlines=True)
        return result
    except subprocess.CalledProcessError as e:
        return str(e)

# Get HTTP headers
def get_http_headers(domain):
    try:
        response = requests.get(f"http://{domain}", timeout=5)
        return response.headers
    except requests.RequestException as e:
        return str(e)

# Analyze website technologies via headers
def analyze_web_tech(headers):
    tech_info = {}
    if 'Server' in headers:
        tech_info['Server'] = headers['Server']
    if 'X-Powered-By' in headers:
        tech_info['X-Powered-By'] = headers['X-Powered-By']
    return tech_info

# Main reconnaissance function
def reconnaissance(domain):
    print(f"Starting reconnaissance on {domain}...\n")

    # 1. Get IP Address
    ip_address = get_ip_address(domain)
    if ip_address:
        print(f"IP Address: {ip_address}")
    else:
        print("Could not resolve domain to IP.")
        return

    # 2. WHOIS Information
    whois_info = get_whois_info(domain)
    print("\nWHOIS Information:")
    print(whois_info)

    # 3. DNS Records
    dns_records = get_dns_records(domain)
    print("\nDNS Records:")
    for record_type, record_data in dns_records.items():
        print(f"{record_type} Record: {record_data}")

    # 4. Open Ports (using nmap)
    print("\nScanning for open ports...")
    open_ports = scan_open_ports(ip_address)
    print(f"Open Ports:\n{open_ports}")

    # 5. HTTP Headers
    print("\nFetching HTTP headers...")
    http_headers = get_http_headers(domain)
    print(f"HTTP Headers:\n{http_headers}")

    # 6. Web Application Technology
    print("\nAnalyzing web technologies...")
    web_tech = analyze_web_tech(http_headers)
    print(f"Web Technologies: {web_tech}")

if __name__ == "__main__":
    domain = input("Enter the domain to gather reconnaissance info: ")
    reconnaissance(domain)
