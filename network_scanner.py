import nmap
import pandas as pd
import socket
from datetime import datetime
import time
import os

class NetworkScanner:
    def __init__(self, db):
        self.nm = nmap.PortScanner()
        self.db = db
    
    def get_local_network(self):
        """Try to automatically detect the local network range"""
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            network_base = '.'.join(local_ip.split('.')[:-1]) + '.0/24'
            return network_base
        except:
            return '192.168.1.0/24'
    
    def scan_network(self, network_range=None):
        """Perform a network scan and save results to database"""
        start_time = time.time()
        
        if not network_range:
            network_range = self.get_local_network()
        
        print(f"Starting scan of: {network_range}")
        devices = []
        
        try:
            # Choose nmap arguments based on privileges:
            # - If running as root we can use SYN scans and OS detection (-sS, -O)
            # - If not root, fall back to TCP connect scan (-sT) and service detection (-sV)
            if hasattr(os, 'geteuid') and os.geteuid() == 0:
                scan_args = '-sS -O -sV --script=banner -T4'
                privilege_note = 'running privileged scan (SYN/OS detection)'
            else:
                scan_args = '-sT -sV -T4'
                privilege_note = 'non-root fallback (TCP connect scan)'

            print(f"Using nmap arguments: {scan_args} ({privilege_note})")
            self.nm.scan(hosts=network_range, arguments=scan_args)
            
            for host in self.nm.all_hosts():
                device_info = {
                    'ip_address': host,
                    'hostname': self.nm[host].hostname() or 'Unknown',
                    'mac_address': 'Unknown',
                    'vendor': 'Unknown',
                    'status': self.nm[host].state(),
                    'os_guess': 'Unknown',
                    'device_type': 'Unknown',
                    'services': [],
                    'last_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                
                # Get MAC address and vendor
                if 'addresses' in self.nm[host]:
                    if 'mac' in self.nm[host]['addresses']:
                        device_info['mac_address'] = self.nm[host]['addresses']['mac']
                        if 'vendor' in self.nm[host] and device_info['mac_address'] in self.nm[host]['vendor']:
                            device_info['vendor'] = self.nm[host]['vendor'][device_info['mac_address']]
                
                # Get OS information
                if 'osmatch' in self.nm[host]:
                    if self.nm[host]['osmatch']:
                        device_info['os_guess'] = self.nm[host]['osmatch'][0]['name']
                
                # Get open ports and services
                if 'tcp' in self.nm[host]:
                    for port in self.nm[host]['tcp']:
                        port_info = self.nm[host]['tcp'][port]
                        if port_info['state'] == 'open':
                            service_info = {
                                'port': port,
                                'service': port_info['name'],
                                'version': port_info.get('version', 'Unknown'),
                                'product': port_info.get('product', 'Unknown')
                            }
                            device_info['services'].append(service_info)
                
                # Infer device type
                device_info['device_type'] = self._infer_device_type(device_info)
                devices.append(device_info)
            
            duration = time.time() - start_time
            
            # Save to database
            session_id = self.db.save_scan_session(network_range, devices, duration)
            
            return {
                'success': True,
                'session_id': session_id,
                'devices_found': len(devices),
                'duration': round(duration, 2),
                'network_range': network_range
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'devices_found': 0,
                'duration': 0
            }
    
    def _infer_device_type(self, device_info):
        """Infer device type based on available information"""
        vendor_lower = device_info['vendor'].lower()
        os_lower = device_info['os_guess'].lower()
        open_ports = [s['port'] for s in device_info['services']]
        
        if any(x in vendor_lower for x in ['apple', 'iphone', 'ipad', 'mac']):
            return 'Apple Device'
        elif any(x in vendor_lower for x in ['samsung', 'android']):
            return 'Android Device'
        elif any(x in vendor_lower for x in ['raspberry', 'pi']):
            return 'Raspberry Pi'
        elif any(x in vendor_lower for x in ['amazon', 'echo']):
            return 'Amazon Alexa'
        elif any(x in vendor_lower for x in ['google', 'nest']):
            return 'Google Smart Device'
        elif any(x in vendor_lower for x in ['tp-link', 'netgear', 'asus', 'd-link', 'linksys']):
            return 'Network Device'
        elif 22 in open_ports and ('linux' in os_lower or not os_lower):
            return 'Linux Server'
        elif any(port in [135, 139, 445] for port in open_ports):
            return 'Windows Computer'
        elif 80 in open_ports or 443 in open_ports:
            return 'Web Server'
        elif not open_ports and device_info['status'] == 'up':
            return 'Generic IoT Device'
        
        return 'Unknown Device'
    
    def quick_scan(self, network_range=None):
        """Quick scan that just finds active devices"""
        if not network_range:
            network_range = self.get_local_network()
        
        self.nm.scan(hosts=network_range, arguments='-sn')
        
        devices = []
        for host in self.nm.all_hosts():
            device = {
                'ip': host,
                'hostname': self.nm[host].hostname() or 'Unknown',
                'mac': 'Unknown',
                'vendor': 'Unknown',
                'status': self.nm[host].state()
            }
            
            if 'addresses' in self.nm[host] and 'mac' in self.nm[host]['addresses']:
                device['mac'] = self.nm[host]['addresses']['mac']
                if 'vendor' in self.nm[host] and device['mac'] in self.nm[host]['vendor']:
                    device['vendor'] = self.nm[host]['vendor'][device['mac']]
            
            devices.append(device)
        
        return devices