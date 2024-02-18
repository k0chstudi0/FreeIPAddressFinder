from flask import Flask, render_template, redirect, request
from datetime import datetime, timedelta
import ipaddress
import nmap
import sqlite3

app = Flask(__name__)
DATABASE = 'ip_database.db'
networks = ["192.168.0.0/24", "192.168.1.0/24"]

# SQLite database setup
def init_db():
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS ips
                 (ip TEXT PRIMARY KEY, online INTEGER, last_up DATETIME, last_down DATETIME)''')
    conn.commit()
    conn.close()


# Function to perform network scan and update database
def perform_scan(network):
    timestamp = datetime.now()
    nm = nmap.PortScanner()
    nm.scan(hosts=network, arguments='-sn')
    for host in nm.all_hosts():
        ip = host
        status = nm[host]['status']['state']
        if status == 'up':
            update_ip_status(ip, 'up', timestamp)
        else:
            update_ip_status(ip, 'down', timestamp)
    # Handle all hosts not yet mentioned in the nmap output but forming part of the network
    possibleHosts = []
    ipv4addresses = ipaddress.IPv4Network(network)
    for ipv4address in ipv4addresses:
        possibleHosts.append(str(ipv4address))
    for host in nm.all_hosts():
        possibleHosts.remove(host)
    for ip in possibleHosts:
        update_ip_status(ip, 'down', timestamp)


# Function to update IP status in the database
def update_ip_status(ip, status, timestamp):
    conn = sqlite3.connect(DATABASE)
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
def get_ips_with_statuses(network):
    network_oktets = network.split('.')
    subnet = network_oktets[0] + "." + network_oktets[1] + "." + network_oktets[2]
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute(f'SELECT ip, online, last_up, last_down FROM ips WHERE ip LIKE "{subnet}%"')
    ips = c.fetchall()
    conn.close()
    sortedIps = []
    for i in range(1,256):
        for ip in ips:
            currentIp = ip[0]
            if int(currentIp.split('.')[-1]) == i:
                sortedIps.append(ip)
    return sortedIps

# Route to display the grid
@app.route('/')
def index():
    main_list = {}
    for network in networks:
        ips = get_ips_with_statuses(network)
        formatted_ips = []
        for ip, online, last_up, last_down in ips:
            formatted_ip = (str(ip),str(last_up),str(last_down))
            if online == 1:
                formatted_ip += ('online',)
            elif online == 0 and last_up is not None and (datetime.strptime(last_up, "%Y-%m-%d %H:%M:%S.%f") > (datetime.now() - timedelta(days=90))):
                formatted_ip += ('unclear',)
            else:
                formatted_ip += ('free',)
            formatted_ips.append(formatted_ip)
        main_list[network] = formatted_ips
    return render_template('index.html', ips=main_list)

# Route to trigger network scan
@app.route('/rescan')
def rescan():
    for network in networks:
        perform_scan(network)
    return redirect("/", code=302)


if __name__ == '__main__':
    init_db()
    for network in networks:
        perform_scan(network)
    app.run(host='0.0.0.0', port=1337, debug=True)
