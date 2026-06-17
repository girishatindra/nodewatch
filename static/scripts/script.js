const socket = io();




document.addEventListener("alpine:init", () => {
    Alpine.store("ip", {
    data:{},
    loading: false,
    error: null,
    });
    Alpine.store("sniffer", {
        packets: [],
        running: false,
        seenIP: {},
        edges: {},
        currentPage: 1,
        pageSize:    100,
        searchField:  'src_ip', 
        searchQuery:  '',
        selectedIP: {},
        osintMode: null,
        ipCount: 0,
    
        
     

        get filteredPackets() {
            if (!this.searchQuery.trim()) return this.packets;
            const q = this.searchQuery.trim().toLowerCase();
            return this.packets.filter(p => {
                const val = p[this.searchField];
                return val && String(val).toLowerCase().startsWith(q);
            });
        },

        get totalPages() {
            return Math.max(1, Math.ceil(this.filteredPackets.length / this.pageSize));
        },

        get currentPackets() {
            if (this.currentPage > this.totalPages) this.currentPage = 1;
            const start = (this.currentPage - 1) * this.pageSize;
            const end   = start + this.pageSize;
            return this.filteredPackets.slice(start, end);
        },

        nextPage() {
            if (this.currentPage < this.totalPages) this.currentPage++;
        },

        prevPage() {
            if (this.currentPage > 1) this.currentPage--;
        },

        get_ip(src_ip, dst_ip, isGraph) {
            if (isGraph) {
                this.selectedIP = { graph_ip: src_ip };
                this.osintMode  = 'graph';
            } else {
                this.selectedIP = { src: src_ip, dst: dst_ip };
                this.osintMode  = 'table';
            }
        },

        addPacket(pkt) {


            if (!this.seenIP[pkt.src_ip]) {
                this.seenIP[pkt.src_ip] = { "ip": pkt.src_ip };
                this.ipCount++;
            }
            if (!this.seenIP[pkt.dst_ip]) {
                this.seenIP[pkt.dst_ip] = { "ip": pkt.dst_ip };
                this.ipCount++;

            }

            const edgeKey = `${pkt.src_ip}->${pkt.dst_ip}`;
            if (!this.edges[edgeKey]) {
                this.edges[edgeKey] = {
                    "src":   pkt.src_ip,
                    "dst":   pkt.dst_ip,
                    "proto": pkt.proto,
                    "count": 0
                };
            }
            this.edges[edgeKey].count++;


            this.packets.push(pkt);
           
            }
          });
});



socket.on("status", (data) => {
    Alpine.store("sniffer").running = data.running;
});

socket.on('disconnect', () => {
    Alpine.store('sniffer').running = false;
    alert("Connection Got Disconnected")

});

socket.on('connect_error', () => {
    Alpine.store('sniffer').running = false;
    alert("An Connection Error Occured, Check Your Connection And Refresh")
});

function startCapture() {
    socket.emit("start_capture");
}

function stopCapture() {
    socket.emit("stop_capture");
}

async function ipQuery(ip) {
    Alpine.store('ip').loading = true;
    Alpine.store('ip').error   = null;
    Alpine.store('ip').data    = {};
    try {
        const response = await fetch('/ip', {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify({ ip: ip })
        });

        let data = {};
        
        try {
            data = await response.json();
        } catch {
            data = { error: `request failed: ${response.status}` };
        }

        if (!response.ok) {
            Alpine.store('ip').error = data.error || `request failed: ${response.status}`;
            return;
        }

        Alpine.store('ip').data = data;
        await new Promise(resolve => setTimeout(resolve, 100));
        show_map();
    }
    catch (error) {
        Alpine.store('ip').error = "connection failed — check your network";
    }
    finally {
        Alpine.store('ip').loading = false;
    }
}

let batch = [];

socket.on('packet', (pkt) => {
    batch.push(pkt);  // just collect
});

setInterval(() => {
    if (batch.length === 0) return;
    batch.forEach(p => Alpine.store('sniffer').addPacket(p));
    batch = [];
}, 500);


let mapInstance = null;

function show_map(){
const ip = Alpine.store('ip').data;
if (!ip.latitude || !ip.longitude) return;
if (mapInstance){
    mapInstance.remove();
    mapInstance = null;
}
mapInstance = L.map('map').setView([ip['latitude'],ip['longitude']], 13,);
var marker = L.marker([ip['latitude'],ip['longitude']]).addTo(mapInstance);
L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {
    maxZoom: 19,
    attribution: '&copy; <a href="http://www.openstreetmap.org/copyright">OpenStreetMap</a>'
}).addTo(mapInstance);
marker.bindPopup(`<b>${ip['ip']}</b><br>${ip['country']},${ip['state']},${ip['city']},${ip["zip_code"]}`).openPopup();

}

let network = null;

function showGraph() {

    if (network) {
    network.destroy();
    network = null;
    }

    const store = Alpine.store('sniffer');

    // nodes from seenIPs
    const nodes = new vis.DataSet(
        Object.values(store.seenIP).map(n => ({
            id:    n.ip,
            label: n.ip,
            font:  { color: 'green', size: 20 },
            shape: 'box',
            title: `packets seen: ${store.edges[Object.keys(store.edges).find(k => k.startsWith(n.ip + '->') || k.endsWith('->' + n.ip))] ? 
                Object.values(store.edges)
                    .filter(e => e.src === n.ip || e.dst === n.ip)
                    .reduce((sum, e) => sum + e.count, 0) : 0}`,
        }))
    );

    // edges from edges dict
    const edges = new vis.DataSet(
        Object.values(store.edges).map(e => ({
            from:   e.src,
            to:     e.dst,
            width:  1,
            label:  `${e.proto} ×${e.count}`,
            font:   { color: '#6b7280', size: 15, align: 'middle' },
            color:  { color: '#374151', highlight: '#58a6ff' },
            arrows: 'to',
           
        }))    
    );


const container = document.getElementById('graph');

const options = {
    physics: {
        enabled: true,
        solver: 'forceAtlas2Based',  // better than barnesHut for star topology
        forceAtlas2Based: {
        gravitationalConstant: -30,   // was -50, less repulsion
        centralGravity:        0.005, // was 0.01, less pull to center
        springLength:          200,
        springConstant:        0.02,  // was 0.08, much looser springs
        damping:               0.8,   // was 0.4, higher damping = settles faster
        avoidOverlap:          1,
    },
        stabilization: {
            enabled:        true,
            iterations:     3000,   // more iterations to find stable state
            updateInterval: 100,    // less frequent updates during stabilization
            fit:            true,
        },
        maxVelocity: 10,    // was 50, lower = less aggressive movement
        minVelocity: 1,     // was 0.1, higher = declares stable sooner

    },
    layout: {
        hierarchical: { enabled: false },  // back to physics layout
        improvedLayout: false,             // let forceAtlas handle it
    },
    interaction: {
        hover:        true,
        zoomView:     true,
        dragView:     true,
        tooltipDelay: 100,
    },
    edges: {
        smooth: { enabled: false },
        arrows: 'to',
    },
    nodes: {
        borderWidth: 1,
        shadow:      false,
    }
};

// freeze after stabilization so it stops consuming CPU


network   = new vis.Network(container, { nodes, edges },options);
    

    // click node to investigate
network.on('click', async (params) => {
        if (params.nodes.length > 0) {
            const ip = params.nodes[0];
            await Alpine.store("sniffer").get_ip(ip,null,true)
            await ipQuery(ip)
        }
});

network.on('stabilized', () => {
    network.setOptions({ physics: { enabled: false } });
});
    
    return network

  
}


window.addEventListener('beforeunload', (event) => {
    stopCapture();
    Alpine.store('sniffer').packets = [];
});
