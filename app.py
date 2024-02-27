from flask import Flask, g, render_template, redirect, request
from datetime import datetime, timedelta
import argparse
import ipaddress
import logging
import nmap
import re
import sqlite3

app = Flask(__name__)
parsed_args = None
ipv4_networks = []
dhcp_ip_addresses = []

RE_IP_ADDRESS = r'''
    ^
    (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.  # First octet
    (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.  # Second octet
    (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.  # Third octet
    (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)    # Fourth octet
    $
    '''
RE_IP_NETWORK = r'''
    ^
    (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.  # First octet
    (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.  # Second octet
    (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.  # Third octet
    (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)    # Fourth octet
    /(?:3[0-2]|[12]?[0-9])                      # CIDR notation (0-32)
    $
    '''
RE_IP_RANGE = r'''
    ^
    (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.   # First octet of first IP
    (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.   # Second octet of first IP
    (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.   # Third octet of first IP
    (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)     # Fourth octet of first IP
    -
    (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.   # First octet of second IP
    (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.   # Second octet of second IP
    (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.   # Third octet of second IP
    (?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)     # Fourth octet of second IP
    $
    '''

# SQLite database setup
def init_db():
    conn = sqlite3.connect(parsed_args.db)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS ips
                 (ip TEXT PRIMARY KEY, online INTEGER, last_up DATETIME, last_down DATETIME)''')
    conn.commit()
    conn.close()


# Function to perform network scan and update database
def perform_scan(ipv4_network):
    timestamp = datetime.now()
    nm = nmap.PortScanner()
    nm.scan(hosts=str(ipv4_network), arguments='-sn')
    for host in nm.all_hosts():
        ip = host
        status = nm[host]['status']['state']
        if status == 'up':
            update_ip_status(ip, 'up', timestamp)
        else:
            update_ip_status(ip, 'down', timestamp)
    # Handle all hosts not yet mentioned in the nmap output but forming part of the network
    possibleHosts = []
    
    for ipv4address in ipv4_network:
        possibleHosts.append(str(ipv4address))
    for host in nm.all_hosts():
        possibleHosts.remove(host)
    for ip in possibleHosts:
        update_ip_status(ip, 'down', timestamp)


# Function to update IP status in the database
def update_ip_status(ip, status, timestamp):
    conn = sqlite3.connect(parsed_args.db)
    c = conn.cursor()
    c.execute(f'SELECT * FROM ips WHERE ip = "{ip}"')
    entry = c.fetchall()
    if status == 'up':
        if entry == []:
            c.execute('INSERT OR REPLACE INTO ips (ip, online, last_up) VALUES (?, ?, ?)', (ip, 1, timestamp))
        else:
            c.execute('UPDATE ips SET online = ?, last_up = ? WHERE ip == ?', (1, timestamp, ip))
    else:   
        if entry == []:
            c.execute('INSERT OR REPLACE INTO ips (ip, online, last_down) VALUES (?, ?, ?)', (ip, 0, timestamp))
        else:
            c.execute('UPDATE ips SET online = ?, last_down = ? WHERE ip == ?', (0, timestamp, ip))
    conn.commit()
    conn.close()


# Function to retrieve IP addresses and their statuses for a given /24 network
def get_ips_with_statuses(ipv4_network):
    conn = sqlite3.connect(parsed_args.db)
    c = conn.cursor()
    c.execute(f'SELECT ip, online, last_up, last_down FROM ips ORDER BY ip') # WHERE ip LIKE "{subnet}%"')
    ips = c.fetchall()
    conn.close()
    ipv4_addresses_with_info = []
    for ip in ips:
        ipv4_address = ipaddress.IPv4Address(ip[0])
        if ipv4_address in ipv4_network:
            ipv4_addresses_with_info.append((ipv4_address,ip[1],ip[2],ip[3]))
    return sorted(ipv4_addresses_with_info)

# Route to display the grid
@app.route('/')
def index():
    main_list = {}
    for ipv4_network in ipv4_networks:
        ips = get_ips_with_statuses(ipv4_network)
        formatted_ips = []
        for ip, online, last_up, last_down in ips:
            formatted_ip = (str(ip),str(last_up),str(last_down))
            if online == 1:
                formatted_ip += ('online',)
            elif online == 0 and last_up is not None and (datetime.strptime(last_up, "%Y-%m-%d %H:%M:%S.%f") > (datetime.now() - timedelta(days=90))):
                formatted_ip += ('unclear',)
            else:
                formatted_ip += ('free',)
            # Process decorators
            if ip == ipv4_network.network_address:
                formatted_ip += ('networkaddress',)
            elif ip == ipv4_network.broadcast_address:
                formatted_ip += ('broadcastaddress',)
            elif ip in dhcp_ip_addresses:
                formatted_ip += ('dhcp',)
            else:
                formatted_ip += ('',)
            formatted_ips.append(formatted_ip)
        main_list[ipv4_network] = formatted_ips
    return render_template('index.html', ips=main_list)


# Route to trigger network scan
@app.route('/rescan')
def rescan():
    for ipv4_network in ipv4_networks:
        perform_scan(ipv4_network)
    return redirect("/", code=302)


def extract_IP_range(range_string):
    result = []
    if range_string.count("-") == 1:
        from_string, to_string = range_string.split("-")
        try:
            from_ip_address = ipaddress.IPv4Address(from_string)
            to_ip_address = ipaddress.IPv4Address(to_string)
        except:
            raise ValueError(f'Error in extracting an IP address from the range {range_string}')
        if from_ip_address > to_ip_address:
            raise ValueError("Start address must be less than end address") 
        current_ip = from_ip_address
        while current_ip <= to_ip_address:
            result.append(current_ip)
            logging.debug(f'Identified {current_ip} as DHCP address.')
            current_ip += 1
    else:
        raise ValueError(f'Range {range_string} must contain exactly one "-".')
    return result


def process_and_check_input():
    global ipv4_networks
    global dhcp_ip_addresses

    ip_address_pattern = re.compile(RE_IP_ADDRESS, re.VERBOSE)
    ip_network_pattern = re.compile(RE_IP_NETWORK, re.VERBOSE)
    ip_range_pattern = re.compile(RE_IP_RANGE, re.VERBOSE)

    # Error for valid networks in scannetwork with a subnet mask lower than /24
    for entry in parsed_args.scannetwork:
        if ip_network_pattern.match(entry):
            try:
                ipv4network = ipaddress.IPv4Network(entry)
                logging.debug(f'{entry} is recognized as a valid IP network.')
            except ValueError:
                logging.warning(f"'{entry}' is not a valid input for --scannetwork. It must be a network in valid CIDR notation. Skipping...")
                continue
            if ipv4network.prefixlen < 24:
                logging.warning(f"'{entry}' is not a valid input for --scannetwork. It must have a /24 prefix length or higher. Skipping...")
            else:
                ipv4_networks.append(ipv4network)
        else:
            logging.warning(f"'{entry}' is not a valid input for --scannetwork. It must be a network in valid CIDR notation. Skipping...")
    
    # Warning for overlapping IP address ranges in scannetwork
    for i, network1 in enumerate(ipv4_networks):
        for network2 in ipv4_networks[i+1:]:
            if network1.overlaps(network2):
                logging.warning(f'Networks {network1} and {network2} overlap!')

    # Error for logical errors in dhcparea
    for definition in parsed_args.dhcparea:
        if ip_address_pattern.match(definition):
            try:
                ipv4_address = ipaddress.IPv4Address(definition)
                logging.debug(f'DHCP definition {definition} is recognized as an IP address.')
                dhcp_ip_addresses.append(ipv4_address)
            except ValueError:
                logging.warning(f'DHCP definition {definition} is not recognized as an IP address. Skipping...')
        elif ip_network_pattern.match(definition):
            try:
                ipv4_network = ipaddress.IPv4Network(definition)
                logging.debug(f'DHCP definition {definition} is recognized as an IP network in CIDR notation.')
                for ipv4_network_address in ipv4_network.hosts():
                    dhcp_ip_addresses.append(ipv4_network_address)
            except ValueError:
                logging.warning(f'DHCP definition {definition} is not recognized as an IP network in CIDR notation. Skipping...')
        elif ip_range_pattern.match(definition):
            try:
                range_addresses = extract_IP_range(definition)
                logging.debug(f'DHCP definition {definition} is recognized as an IP range.')
                for range_address in range_addresses:
                    dhcp_ip_addresses.append(range_address)
            except ValueError:
                logging.warning(f'DHCP definition {definition} is not recognized as an IP range like "192.168.1.100-192.168.1.200". Skipping...')
        else:
            logging.warning(f"'{entry}' is not a valid input for --dhcparea. It must be a single IP address (without subnet mask like \"192.168.1.42\"), a CIDR network (with network mask like \"192.168.1.0/28\"), or a specific range (like \"192.168.1.100-192.168.1.200\"). Skipping...")


def parse_arguments():
    global parsed_args
    
    parser = argparse.ArgumentParser(description='Python Flask service that frequently performs network-wide ICMP sweeps to determine online hosts and IP addresses in use.')

    # Add arguments
    parser.add_argument('--db', type=str, default="ip_database.db", help='Name of the local SQLite database.')
    parser.add_argument('--ip', '-i', default='0.0.0.0', help='IP address to bind listener to.')
    parser.add_argument('--port', '-p', default=1337, help='Port to bind listener to.')
    parser.add_argument('--scannetwork', '-s', action='append', default=[], help='Specifies network segment to scan in CIDR syntax (e.g., 192.168.0.1/24). Use multiple )')
    parser.add_argument('--dhcparea', '-d', action='append', default=[], help='Specifies single IP addresses (without subnet mask like "192.168.1.42"), CIDR networks (with network mask like "192.168.1.0/28"), or specific ranges (like "192.168.1.100-192.168.1.200") as DHCP area. This only affects the presentation in the web view.')
    parser.add_argument('--loglevel', '-l', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'], default='INFO', help="Set the logging level")
    
    # Parse and store the arguments
    parsed_args = parser.parse_args()

    numeric_log_level = getattr(logging, parsed_args.loglevel.upper(), None)
    if not isinstance(numeric_log_level, int):
        raise ValueError('Invalid log level: %s' % parsed_args.loglevel)

    logging.basicConfig(level=numeric_log_level, format='%(asctime)s - %(levelname)s - %(message)s')

    # Set default scan network manually because the previous default hat to be set to an empty list 
    if parsed_args.scannetwork == []:
        parsed_args.scannetwork.append("192.168.1.0/24")


def main():
    parse_arguments()
    process_and_check_input()
    #init_db()
    #for ipv4_network in ipv4_networks:
    #    perform_scan(ipv4_network)
    app.run(host=parsed_args.ip, port=parsed_args.port, debug=True)


if __name__ == '__main__':
    main()