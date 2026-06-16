# NodeWatch - network observation and OSINT threat-hunting platform

<div align="center">
  
  <img width="70%" alt="NodeWatch" src="https://github.com/user-attachments/assets/fa260788-b18a-4405-971e-3b5844f6a843" />

</div>

<div align="center">
  
[![BACKEND](https://img.shields.io/badge/Backend-Flask-skyblue?style=for-the-badge&labelColor=orange)](https://www.python.org/)
[![Frontend](https://img.shields.io/badge/Frontend-alpine.js-skyblue?style=for-the-badge&labelColor=orange)](https://docs.python.org/3/library/tkinter.html)
[![Graph](https://img.shields.io/badge/Graph-Vis.js-skyblue?style=for-the-badge&labelColor=orange)](https://pyinstaller.org)
[![Map](https://img.shields.io/badge/MAP-Leaflet.js-skyblue?style=for-the-badge&labelColor=orange)](https://haveibeenpwned.com/api/v3)
[![API](https://img.shields.io/badge/API-ipquery-skyblue?style=for-the-badge&labelColor=orange)](https://www.microsoft.com/en-in/windows?r=1)

</div>

<hr>

<br>
<br>

<div align='center'>

 <img width="70%" alt="demo" src="https://github.com/user-attachments/assets/cb7db475-f9cf-484b-aacc-98208648e306" />


</div>

<br>
<br>

<div align="center">
  
***In an era dominated by automated security alerts and AI, NodeWatch reclaims the power of analyst intuition.***

</div>

NodeWatch is a host-based network observation and OSINT threat-hunting platform built around a single philosophy — the analyst decides, not the machine.
Unlike traditional security tools that rely on automated verdicts and machine-generated alerts, NodeWatch surfaces raw network data clearly and lets the human draw their own conclusions. Every indicator is a technical fact. Every conclusion is the analyst's own.

<br>
<br>

<hr>

<br>

# About

<br>

***What Does NodeWatch Do ?***

NodeWatch captures live host traffic using Scapy and streams it to an interactive browser dashboard in real time. Traffic is presented in two forms: a paginated packet table with search and filtering, and an interactive network graph mapping every IP relationship observed during the capture session.
For any external IP, the analyst can trigger on-demand OSINT enrichment via the IPQuery API returning geolocation, ASN, ISP, VPN,Tor,datacenter flags, a fraud risk score, and the geolocation plotted live on an interactive map. Every port links directly to the SANS Internet Storm Center for real-time community threat intelligence. Every service name links to contextual search. Every ASN links to an RDAP lookup engine.
No automated threat verdicts. No cloud dependency. No infrastructure. One command and you're hunting.

<br>
<br>

***What Tech Stack Does NodeWatch Use ?***

- Scapy - Capturing live packets
- Flask SocketIO - Streaming the packets to frontend
- Flask - Backend
- Alpine.js - Frontend
- Vis.js - Interactive graphs
- Leaflet.js - Interavtive maps

<br>
<br>

***What Makes NodeWatch Different ?***

Most tools are desgined to be user friendly with interpretation done by complex alogrithims and detection engines, NodeWatch lets the user interpret the data, It provides all the context required for a human to make a judgement, at its current form NodeWatch is host based and monitors the nodes connecting to the host, its primary purpose is to present data in different forms providing different angles to look from and provide the tools to gain context and build the evidence to make judgement and interptetations, currently NodeWatch is an MVP only providing packets as table and network graph with only ipquery and hyperlinks to SANS Internet Storm Center as OSINT tools

<br>
<br>

***How To Use NodeWatch***

1. Clone this repo
   ```bash
   git clone https://github.com/girishatindra/nodewatch.git
   ```
2. Start a virtual environment
   ```bash
   python -m venv venv
   ```
3. Intall the requirements
   ```bash
   pip install -r requirements.txt
   ```
4. Run the flask server
   ```bash
   flask --run app.py
   ```
To get a basic understanding on how to use it, you can watch the demo

***Will NodeWatch Expand ?***

Currently as an MVP NodeWatch only fullfills the basic idea behind it, its desgined to be expanded to add more kinds of visual representations etc
