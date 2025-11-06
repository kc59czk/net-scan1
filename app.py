from flask import Flask, render_template, request, jsonify, redirect, url_for
from db_manager import Database
from network_scanner import NetworkScanner
import json
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'

# Initialize database and scanner
db = Database()
scanner = NetworkScanner(db)

@app.route('/')
def index():
    """Main dashboard"""
    stats = db.get_statistics()
    recent_scans = db.get_scan_sessions(limit=5)
    recent_devices = db.get_all_devices()[:10]
    
    return render_template('index.html', 
                         stats=stats, 
                         recent_scans=recent_scans,
                         recent_devices=recent_devices)

@app.route('/scan', methods=['GET', 'POST'])
def scan_network():
    """Perform network scan"""
    if request.method == 'POST':
        network_range = request.form.get('network_range', '').strip()
        if not network_range:
            network_range = None
        
        result = scanner.scan_network(network_range)
        
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return jsonify(result)
        else:
            if result['success']:
                return redirect(url_for('scan_results', session_id=result['session_id']))
            else:
                return render_template('scan.html', error=result['error'])
    
    return render_template('scan.html')

@app.route('/scan/<int:session_id>')
def scan_results(session_id):
    """Show results of a specific scan"""
    devices = db.get_devices_from_session(session_id)
    scan_sessions = db.get_scan_sessions()
    current_session = next((s for s in scan_sessions if s['id'] == session_id), None)
    
    return render_template('devices.html', 
                         devices=devices, 
                         session_id=session_id,
                         current_session=current_session,
                         scan_sessions=scan_sessions)

@app.route('/devices')
def all_devices():
    """Show all known devices"""
    devices = db.get_all_devices()
    return render_template('devices.html', devices=devices, all_devices=True)

@app.route('/device/<int:device_id>')
def device_detail(device_id):
    """Show detailed information for a device"""
    device = db.get_device_detail(device_id)
    return render_template('device_detail.html', device=device)

@app.route('/history')
def scan_history():
    """Show scan history"""
    scan_sessions = db.get_scan_sessions(limit=20)
    return render_template('history.html', scan_sessions=scan_sessions)

@app.route('/statistics')
def statistics():
    """Show detailed statistics"""
    stats = db.get_statistics()
    return render_template('stats.html', stats=stats)

@app.route('/api/quick-scan')
def api_quick_scan():
    """API endpoint for quick scan"""
    network_range = request.args.get('network_range')
    devices = scanner.quick_scan(network_range)
    return jsonify(devices)

@app.route('/api/statistics')
def api_statistics():
    """API endpoint for statistics"""
    stats = db.get_statistics()
    return jsonify(stats)

@app.template_filter('datetime')
def format_datetime(value):
    """Format datetime for templates"""
    if isinstance(value, str):
        return value
    return value.strftime('%Y-%m-%d %H:%M:%S')

@app.template_filter('from_json')
def from_json(value):
    """Parse JSON string"""
    try:
        return json.loads(value)
    except:
        return value

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)