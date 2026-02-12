print("Checking for life... System Online.")
import pandas as pd
import os
from sklearn.ensemble import IsolationForest
import paramiko
from dotenv import load_dotenv
from scapy.all import sniff, IP # <--- NEW: Import Scapy tools

load_dotenv()

# We'll use a simple list to keep track of the last few packets as a "rolling window"
packet_buffer = []

def deploy_tactical_unit(attacker_ip):
    print(f"🚀 [ACTION] Deploying Kali Tactical Unit against {attacker_ip}...")
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(
            os.getenv('KALI_IP'), 
            username=os.getenv('KALI_USER'), 
            password=os.getenv('KALI_PASS')
        )
        cmd = f"bash ~/Tactical_Kali/kali_vuln_scanner.sh {attacker_ip}"
        ssh.exec_command(cmd)
        print(f"✅ [SUCCESS] Attack Neutralized & Scanned: {attacker_ip}")
    except Exception as e:
        print(f"❌ [SSH ERROR]: {e}")
    finally:
        ssh.close()

# This replaces your old "while True" logic
packet_buffer = []

ip_buffers = {} 

def process_packet(packet):
    global ip_buffers # Use a dictionary to track each IP separately
    
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        
        # 🛡️ 1. Ignore your own machine (and loopback)
        if src_ip == "192.168.187.48" or src_ip == "127.0.0.1":
            return

        pkt_size = len(packet)
        
        # 📁 2. Create a folder for this IP if it's new
        if src_ip not in ip_buffers:
            ip_buffers[src_ip] = []
            
        # ✍️ 3. Add data to this specific IP's buffer
        ip_buffers[src_ip].append({'packet_size': pkt_size})
        
        # 📏 4. Maintain a sliding window for this specific IP
        if len(ip_buffers[src_ip]) > 50:
            ip_buffers[src_ip].pop(0)

        # 🧠 5. Analyze once we have enough data on THIS specific IP
        if len(ip_buffers[src_ip]) >= 20:
            df_live = pd.DataFrame(ip_buffers[src_ip])
            
            # Using contamination=0.2 for a balance between speed and accuracy
            model = IsolationForest(contamination=0.2, random_state=42)
            df_live['anomaly'] = model.fit_predict(df_live[['packet_size']])
            
            # 🚨 6. Check if the latest behavior of THIS IP is anomalous
            if df_live.iloc[-1]['anomaly'] == -1:
                # Double check to ignore the router if its IP changed
                if src_ip != "192.168.181.1": 
                    print(f"🚨 LIVE THREAT DETECTED: {src_ip}")
                    deploy_tactical_unit(src_ip)
                    
                    # Reset only this IP's buffer after action
                    ip_buffers[src_ip] = []
def main():
    print("🧠 AI Detector LIVE MODE starting...")
    print("👂 Listening for Kali attacks on the network...")
    
    try:
        # NOTE: Make sure iface="Wi-Fi" matches your Windows adapter name!
        sniff(iface="Wi-Fi", prn=process_packet, store=0)
    except Exception as e:
        print(f"❌ ERROR: {e}")
        print("💡 Hint: Did you install Npcap and run as Administrator?")

if __name__ == "__main__":
    main()