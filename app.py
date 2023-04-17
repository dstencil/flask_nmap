from flask import Flask, render_template, request, jsonify, redirect, url_for
import nmap
import networkx as nx
import matplotlib.pyplot as plt
import json

app = Flask(__name__)

# Temporary storage for network range


# Step 1: Perform network discovery using Nmap
# Step 1: Perform network discovery using Nmap
def perform_network_discovery(network_range):
    # Create an NmapScanner object
    nm = nmap.PortScanner()

    # Perform network scan using Nmap
    nm.scan(hosts=network_range, arguments='-sn')

    # Extract devices information from the scan results
    devices = []
    for ip in nm.all_hosts():
        device = {'ip': ip}
        if 'hostnames' in nm[ip]:
            device['hostname'] = nm[ip]['hostnames'][0]['name']
        else:
            device['hostname'] = ''
        if 'addresses' in nm[ip]:
            device['mac'] = nm[ip]['addresses'].get('mac', '').upper()
            device['ipv4'] = nm[ip]['addresses'].get('ipv4', '')
            device['ipv6'] = nm[ip]['addresses'].get('ipv6', '')
        else:
            device['mac'] = ''
            device['ipv4'] = ''
            device['ipv6'] = ''
        if 'vendor' in nm[ip]:
            device['vendor'] = nm[ip]['vendor'].get(device['mac'], '')
        else:
            device['vendor'] = ''
        devices.append(device)

    return devices

# Step 2: Build network graph using NetworkX
def build_network_graph(devices):
    # Create an empty directed graph
    G = nx.DiGraph()

    # Add devices as nodes to the graph
    for device in devices:
        G.add_node(device['ip'], label=device['ip'])

    # Add edges between devices based on network connections
    for device in devices:
        for connected_ip in device.get('connected_ips', []):
            if connected_ip in G:
                G.add_edge(device['ip'], connected_ip)

    return G

# Step 3: Visualize network topology with NetworkX and Matplotlib
def visualize_network_topology(G):
    # Generate network topology plot using NetworkX and Matplotlib
    pos = nx.spring_layout(G)
    labels = nx.get_node_attributes(G, 'label')
    labels = {k: '\n'.join(v.split('\n')[:2]) for k, v in labels.items()}  # Limit labels to 2 lines
    nx.draw_networkx_labels(G, pos, labels=labels)
    nx.draw(G, pos, node_color='lightblue', node_size=500, edge_color='gray', linewidths=0.5, arrowsize=10)

    # Save the network topology plot as an image
    plt.title("Network Topology")
    plt.axis('off')
    plt.savefig('static/network_topology.png', format='png')  # Save the plot as an image in 'static' folder
    plt.close()

@app.route('/')
def index():
    return render_template('form.html')

@app.route('/map', methods=['POST'])
def map():
    # Check if the request method is POST
    if request.method == 'POST':
        # Get the value of 'network_range' from the form data
        network_range = request.form.get('network_range')
        
        # Perform network scanning and retrieve list of devices
        devices = perform_network_discovery(network_range)
        
        # Build network graph
        G = build_network_graph(devices)
        
        # Visualize network topology
        visualize_network_topology(G)
        
        # Return the list of devices and network topology image in the response
        return render_template('map.html', devices=devices, topology_image='static/network_topology.png')


if __name__ == '__main__':
    app.run(debug=True)
