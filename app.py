from scapy.all import sniff
from flask import Flask, render_template, request, jsonify
from flask_socketio import SocketIO, emit
import threading
import socket
import requests
import ipaddress



def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
    except Exception:
        local_ip = "127.0.0.1"
    finally:
        s.close()
    return local_ip


def get_service_name(port, proto):
    try:
        service = socket.getservbyport(port, proto)
        return {"message": service, "url": f"https://www.google.com/search?q=%22{service}%22"}
    except OSError:
        return {"message": "unknown", "url": f"https://www.google.com/search?q=%22{proto}+{port}%22"}


LOCAL_IP = get_local_ip()

def packet_callback(packet):
    data = {}
    local_ip = LOCAL_IP
    data['local_ip'] = local_ip
    if "ARP" in packet:
        data["src_ip"] = packet.psrc
        data["dst_ip"] = packet.pdst
        data["proto"] = "ARP"
        data["info"] = "Request" if packet["ARP"].op == 1 else "Reply"
        data["length"] = len(packet["Raw"].load) if "Raw" in packet else "0"
        data["src_port"] = "N/A"
        data["src_port_url"] = "#"
        data["dst_port"] = "N/A"
        data["dst_port_url"] = "#"
        data["service"] = "N/A"
        data["service_url"] = "#"

    elif "IP" in packet:
        data["src_ip"] = packet['IP'].src
        data["dst_ip"] = packet['IP'].dst
        if "TCP" in packet:
            data["proto"] = "TCP"
            data["src_port"] = packet["TCP"].sport
            data["src_port_url"] = f'https://isc.sans.edu/data/port/{packet["TCP"].sport}'
            data["dst_port"] = packet["TCP"].dport
            data["dst_port_url"] = f'https://isc.sans.edu/data/port/{packet["TCP"].dport}'
            data["info"] = f"Flags: {str(packet['TCP'].flags)}"
            data["length"] = len(packet["Raw"].load) if "Raw" in packet else "0"
            service = get_service_name(packet["TCP"].dport, "tcp")
            data["service"] = service['message']
            data["service_url"] = service['url']

        elif "UDP" in packet:
            data["proto"] = "UDP"
            data["src_port"] = packet["UDP"].sport
            data["src_port_url"] = f'https://isc.sans.edu/data/port/{packet["UDP"].sport}'
            data["dst_port"] = packet["UDP"].dport
            data["dst_port_url"] = f'https://isc.sans.edu/data/port/{packet["UDP"].dport}'
            data["info"] = "datagram"
            data["length"] = len(packet["Raw"].load) if "Raw" in packet else "0"
            service = get_service_name(packet["UDP"].dport, "udp")
            data["service"] = service['message']
            data["service_url"] = service['url']
        elif "ICMP" in packet:
            data["proto"] = "ICMP"
            data["info"] = f"Type {packet['ICMP'].type}, Code {packet['ICMP'].code}"
            data["length"] = len(packet["Raw"].load) if "Raw" in packet else "0"
            data["src_port"] = "N/A"
            data["src_port_url"] = "#"
            data["dst_port"] = "N/A"
            data["dst_port_url"] = "#"
            data["service"] = "N/A"
            data["service_url"] = "#"
        else:
            return
    else:
        return
    
    if data:
        socketio.emit("packet", data)

def run_capture():
    global capture_running
    sniff(prn= packet_callback, store=False, stop_filter=lambda _: not capture_running)

def get_ip_query(ip):
    try:
        response = requests.get(f'https://api.ipquery.io/{ip}', timeout=5)
        response.raise_for_status()
        data = response.json()
        return {
            'ip':            data['ip'],
            'ip_url':        f"https://isc.sans.edu/ipinfo/{data['ip']}",
            'asn':           data['isp']['asn'],
            'asn_url':       f"https://client.rdap.org/?type=autnum&object={data['isp']['asn']}",
            'org':           data['isp']['org'],
            'org_url':       f"https://www.google.com/search?q=%22{data['isp']['org']}%22",
            'isp':           data['isp']['isp'],
            'isp_url':       f"https://www.google.com/search?q=%22{data['isp']['isp']}%22",
            'longitude':     data['location']['longitude'],
            'latitude':      data['location']['latitude'],
            'country':       data['location']['country'],
            'state':         data['location']['state'],
            'zip_code':      data['location']['zipcode'],
            'city':          data['location']['city'],
            'is_mobile':     str(data['risk']['is_mobile']).lower(),
            'is_vpn':        str(data['risk']['is_vpn']).lower(),
            'is_tor':        str(data['risk']['is_tor']).lower(),
            'is_datacenter': str(data['risk']['is_datacenter']).lower(),
            'risk_score':    str(data['risk']['risk_score']).lower(),
        }
    except requests.Timeout:
        return {"error": "request timed out"}
    except requests.RequestException as e:
        return {"error": f"api request failed: {str(e)}"}
    except KeyError as e:
        return {"error": f"unexpected api response: {str(e)}"}


        

app = Flask(__name__)
socketio = SocketIO(app, cors_allowed_origins=['http://localhost:5000', 'http://127.0.0.1:5000'],manage_session=False,async_mode="threading")
capture_running = False

@app.route("/")
def hello_world():
    return render_template("index.html")

@socketio.on("start_capture")
def handle_start():
    global capture_running, LOCAL_IP
    if not capture_running:
        LOCAL_IP = get_local_ip()
        capture_running = True
        threading.Thread(target=run_capture, daemon=True).start()
        emit("status", {"msg": "capturing", "running": True})

@socketio.on("stop_capture")
def handle_stop():
    global capture_running
    capture_running = False
    emit("status", {"msg": "stopped", "running": False})


@app.route("/ip", methods=['POST'])
def ip_query():
    body = request.get_json()
    if not body or 'ip' not in body:
        return jsonify({"error": "missing ip"}), 400
    if not is_public_ip(body['ip']):
        return jsonify({"error": "private or invalid ip"}), 400
    result = get_ip_query(body['ip'])
    if 'error' in result:
        return jsonify(result), 500
    return jsonify(result)

if __name__ == '__main__': 
    socketio.run(app, port=5000, debug=False) 


