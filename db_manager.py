import sqlite3
import json
from datetime import datetime
from contextlib import contextmanager

class Database:
    def __init__(self, db_path='network_inventory.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        with self.get_connection() as conn:
            # Scan sessions table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS scan_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    network_range TEXT,
                    total_devices INTEGER,
                    duration_seconds REAL
                )
            ''')
            
            # Devices table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_session_id INTEGER,
                    ip_address TEXT NOT NULL,
                    mac_address TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    os_guess TEXT,
                    device_type TEXT,
                    status TEXT,
                    first_seen DATETIME,
                    last_seen DATETIME,
                    FOREIGN KEY (scan_session_id) REFERENCES scan_sessions (id)
                )
            ''')
            
            # Services table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    port INTEGER,
                    service_name TEXT,
                    version TEXT,
                    product TEXT,
                    FOREIGN KEY (device_id) REFERENCES devices (id)
                )
            ''')
            
            # Device history table for tracking changes
            conn.execute('''
                CREATE TABLE IF NOT EXISTS device_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT,
                    status TEXT,
                    open_ports TEXT,
                    FOREIGN KEY (device_id) REFERENCES devices (id)
                )
            ''')
            
            conn.commit()
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def save_scan_session(self, network_range, devices, duration):
        """Save a complete scan session to database"""
        with self.get_connection() as conn:
            # Insert scan session
            cursor = conn.execute('''
                INSERT INTO scan_sessions (network_range, total_devices, duration_seconds)
                VALUES (?, ?, ?)
            ''', (network_range, len(devices), duration))
            
            session_id = cursor.lastrowid
            
            # Insert devices and their services
            for device in devices:
                # Insert or update device
                cursor = conn.execute('''
                    INSERT OR REPLACE INTO devices 
                    (scan_session_id, ip_address, mac_address, hostname, vendor, os_guess, device_type, status, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 
                            COALESCE((SELECT first_seen FROM devices WHERE ip_address = ?), CURRENT_TIMESTAMP),
                            CURRENT_TIMESTAMP)
                ''', (session_id, device['ip_address'], device['mac_address'], device['hostname'], 
                      device['vendor'], device['os_guess'], device['device_type'], device['status'],
                      device['ip_address']))
                
                device_id = cursor.lastrowid
                if not device_id:
                    # If it was an UPDATE, get the existing device ID
                    cursor = conn.execute('SELECT id FROM devices WHERE ip_address = ?', (device['ip_address'],))
                    result = cursor.fetchone()
                    device_id = result['id'] if result else None
                
                # Save device history
                open_ports = json.dumps([service['port'] for service in device['services']])
                conn.execute('''
                    INSERT INTO device_history (device_id, ip_address, status, open_ports)
                    VALUES (?, ?, ?, ?)
                ''', (device_id, device['ip_address'], device['status'], open_ports))
                
                # Clear existing services for this device
                conn.execute('DELETE FROM services WHERE device_id = ?', (device_id,))
                
                # Insert new services
                for service in device['services']:
                    conn.execute('''
                        INSERT INTO services (device_id, port, service_name, version, product)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (device_id, service['port'], service['service'], service['version'], service['product']))
            
            conn.commit()
            return session_id
    
    def get_scan_sessions(self, limit=10):
        """Get recent scan sessions"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT * FROM scan_sessions 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_devices_from_session(self, session_id):
        """Get all devices from a specific scan session"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT d.*, GROUP_CONCAT(s.port) as ports
                FROM devices d
                LEFT JOIN services s ON d.id = s.device_id
                WHERE d.scan_session_id = ?
                GROUP BY d.id
            ''', (session_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_all_devices(self):
        """Get the most recent status of all unique devices"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT d.*, 
                       (SELECT GROUP_CONCAT(port) FROM services WHERE device_id = d.id) as ports,
                       (SELECT COUNT(*) FROM device_history WHERE device_id = d.id) as scan_count
                FROM devices d
                WHERE d.last_seen = (SELECT MAX(last_seen) FROM devices WHERE ip_address = d.ip_address)
                ORDER BY d.last_seen DESC
            ''')
            return [dict(row) for row in cursor.fetchall()]
    
    def get_device_detail(self, device_id):
        """Get detailed information for a specific device"""
        with self.get_connection() as conn:
            # Get device info
            cursor = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,))
            device = dict(cursor.fetchone())
            
            # Get services
            cursor = conn.execute('SELECT * FROM services WHERE device_id = ?', (device_id,))
            device['services'] = [dict(row) for row in cursor.fetchall()]
            
            # Get history
            cursor = conn.execute('''
                SELECT * FROM device_history 
                WHERE device_id = ? 
                ORDER BY timestamp DESC 
                LIMIT 20
            ''', (device_id,))
            device['history'] = [dict(row) for row in cursor.fetchall()]
            
            return device
    
    def get_statistics(self):
        """Get various statistics about the network"""
        with self.get_connection() as conn:
            stats = {}
            
            # Total devices ever seen
            cursor = conn.execute('SELECT COUNT(DISTINCT ip_address) as count FROM devices')
            stats['total_unique_devices'] = cursor.fetchone()['count']
            
            # Currently active devices (last 24 hours)
            cursor = conn.execute('''
                SELECT COUNT(DISTINCT ip_address) as count 
                FROM devices 
                WHERE last_seen > datetime('now', '-1 day')
            ''')
            stats['recently_active'] = cursor.fetchone()['count']
            
            # Devices by type
            cursor = conn.execute('''
                SELECT device_type, COUNT(*) as count 
                FROM devices 
                WHERE last_seen = (SELECT MAX(last_seen) FROM devices d2 WHERE d2.ip_address = devices.ip_address)
                GROUP BY device_type
            ''')
            stats['devices_by_type'] = {row['device_type']: row['count'] for row in cursor.fetchall()}
            
            # Most common vendors
            cursor = conn.execute('''
                SELECT vendor, COUNT(*) as count 
                FROM devices 
                WHERE vendor != 'Unknown' 
                GROUP BY vendor 
                ORDER BY count DESC 
                LIMIT 10
            ''')
            stats['top_vendors'] = {row['vendor']: row['count'] for row in cursor.fetchall()}
            
            # Scan history
            cursor = conn.execute('''
                SELECT DATE(timestamp) as date, COUNT(*) as scan_count
                FROM scan_sessions
                GROUP BY DATE(timestamp)
                ORDER BY date DESC
                LIMIT 7
            ''')
            stats['recent_scans'] = [dict(row) for row in cursor.fetchall()]
            
            return stats

import sqlite3
import json
from datetime import datetime
from contextlib import contextmanager

class Database:
    def __init__(self, db_path='network_inventory.db'):
        self.db_path = db_path
        self.init_database()
    
    def init_database(self):
        """Initialize database tables"""
        with self.get_connection() as conn:
            # Scan sessions table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS scan_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    network_range TEXT,
                    total_devices INTEGER,
                    duration_seconds REAL
                )
            ''')
            
            # Devices table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_session_id INTEGER,
                    ip_address TEXT NOT NULL,
                    mac_address TEXT,
                    hostname TEXT,
                    vendor TEXT,
                    os_guess TEXT,
                    device_type TEXT,
                    status TEXT,
                    first_seen DATETIME,
                    last_seen DATETIME,
                    FOREIGN KEY (scan_session_id) REFERENCES scan_sessions (id)
                )
            ''')
            
            # Services table
            conn.execute('''
                CREATE TABLE IF NOT EXISTS services (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    port INTEGER,
                    service_name TEXT,
                    version TEXT,
                    product TEXT,
                    FOREIGN KEY (device_id) REFERENCES devices (id)
                )
            ''')
            
            # Device history table for tracking changes
            conn.execute('''
                CREATE TABLE IF NOT EXISTS device_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    ip_address TEXT,
                    status TEXT,
                    open_ports TEXT,
                    FOREIGN KEY (device_id) REFERENCES devices (id)
                )
            ''')
            
            conn.commit()
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()
    
    def save_scan_session(self, network_range, devices, duration):
        """Save a complete scan session to database"""
        with self.get_connection() as conn:
            # Insert scan session
            cursor = conn.execute('''
                INSERT INTO scan_sessions (network_range, total_devices, duration_seconds)
                VALUES (?, ?, ?)
            ''', (network_range, len(devices), duration))
            
            session_id = cursor.lastrowid
            
            # Insert devices and their services
            for device in devices:
                # Insert or update device
                cursor = conn.execute('''
                    INSERT OR REPLACE INTO devices 
                    (scan_session_id, ip_address, mac_address, hostname, vendor, os_guess, device_type, status, first_seen, last_seen)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, 
                            COALESCE((SELECT first_seen FROM devices WHERE ip_address = ?), CURRENT_TIMESTAMP),
                            CURRENT_TIMESTAMP)
                ''', (session_id, device['ip_address'], device['mac_address'], device['hostname'], 
                      device['vendor'], device['os_guess'], device['device_type'], device['status'],
                      device['ip_address']))
                
                device_id = cursor.lastrowid
                if not device_id:
                    # If it was an UPDATE, get the existing device ID
                    cursor = conn.execute('SELECT id FROM devices WHERE ip_address = ?', (device['ip_address'],))
                    result = cursor.fetchone()
                    device_id = result['id'] if result else None
                
                # Save device history
                open_ports = json.dumps([service['port'] for service in device['services']])
                conn.execute('''
                    INSERT INTO device_history (device_id, ip_address, status, open_ports)
                    VALUES (?, ?, ?, ?)
                ''', (device_id, device['ip_address'], device['status'], open_ports))
                
                # Clear existing services for this device
                conn.execute('DELETE FROM services WHERE device_id = ?', (device_id,))
                
                # Insert new services
                for service in device['services']:
                    conn.execute('''
                        INSERT INTO services (device_id, port, service_name, version, product)
                        VALUES (?, ?, ?, ?, ?)
                    ''', (device_id, service['port'], service['service'], service['version'], service['product']))
            
            conn.commit()
            return session_id
    
    def get_scan_sessions(self, limit=10):
        """Get recent scan sessions"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT * FROM scan_sessions 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_devices_from_session(self, session_id):
        """Get all devices from a specific scan session"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT d.*, GROUP_CONCAT(s.port) as ports
                FROM devices d
                LEFT JOIN services s ON d.id = s.device_id
                WHERE d.scan_session_id = ?
                GROUP BY d.id
            ''', (session_id,))
            return [dict(row) for row in cursor.fetchall()]
    
    def get_all_devices(self):
        """Get the most recent status of all unique devices"""
        with self.get_connection() as conn:
            cursor = conn.execute('''
                SELECT d.*, 
                       (SELECT GROUP_CONCAT(port) FROM services WHERE device_id = d.id) as ports,
                       (SELECT COUNT(*) FROM device_history WHERE device_id = d.id) as scan_count
                FROM devices d
                WHERE d.last_seen = (SELECT MAX(last_seen) FROM devices WHERE ip_address = d.ip_address)
                ORDER BY d.last_seen DESC
            ''')
            return [dict(row) for row in cursor.fetchall()]
    
    def get_device_detail(self, device_id):
        """Get detailed information for a specific device"""
        with self.get_connection() as conn:
            # Get device info
            cursor = conn.execute('SELECT * FROM devices WHERE id = ?', (device_id,))
            device = dict(cursor.fetchone())
            
            # Get services
            cursor = conn.execute('SELECT * FROM services WHERE device_id = ?', (device_id,))
            device['services'] = [dict(row) for row in cursor.fetchall()]
            
            # Get history
            cursor = conn.execute('''
                SELECT * FROM device_history 
                WHERE device_id = ? 
                ORDER BY timestamp DESC 
                LIMIT 20
            ''', (device_id,))
            device['history'] = [dict(row) for row in cursor.fetchall()]
            
            return device
    
    def get_statistics(self):
        """Get various statistics about the network"""
        with self.get_connection() as conn:
            stats = {}
            
            # Total devices ever seen
            cursor = conn.execute('SELECT COUNT(DISTINCT ip_address) as count FROM devices')
            stats['total_unique_devices'] = cursor.fetchone()['count']
            
            # Currently active devices (last 24 hours)
            cursor = conn.execute('''
                SELECT COUNT(DISTINCT ip_address) as count 
                FROM devices 
                WHERE last_seen > datetime('now', '-1 day')
            ''')
            stats['recently_active'] = cursor.fetchone()['count']
            
            # Devices by type
            cursor = conn.execute('''
                SELECT device_type, COUNT(*) as count 
                FROM devices 
                WHERE last_seen = (SELECT MAX(last_seen) FROM devices d2 WHERE d2.ip_address = devices.ip_address)
                GROUP BY device_type
            ''')
            stats['devices_by_type'] = {row['device_type']: row['count'] for row in cursor.fetchall()}
            
            # Most common vendors
            cursor = conn.execute('''
                SELECT vendor, COUNT(*) as count 
                FROM devices 
                WHERE vendor != 'Unknown' 
                GROUP BY vendor 
                ORDER BY count DESC 
                LIMIT 10
            ''')
            stats['top_vendors'] = {row['vendor']: row['count'] for row in cursor.fetchall()}
            
            # Scan history
            cursor = conn.execute('''
                SELECT DATE(timestamp) as date, COUNT(*) as scan_count
                FROM scan_sessions
                GROUP BY DATE(timestamp)
                ORDER BY date DESC
                LIMIT 7
            ''')
            stats['recent_scans'] = [dict(row) for row in cursor.fetchall()]
            
            return stats