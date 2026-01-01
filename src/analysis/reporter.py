"""
Project Airdump - Report Generator

Generate analysis reports in various formats:
- HTML reports with interactive maps
- JSON for data export
- CSV for spreadsheet analysis
"""

import logging
import json
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any

logger = logging.getLogger(__name__)

# Try to import optional dependencies
try:
    import folium
    FOLIUM_AVAILABLE = True
except ImportError:
    FOLIUM_AVAILABLE = False
    logger.warning("folium not installed - map generation disabled")

try:
    from jinja2 import Template, Environment, FileSystemLoader
    JINJA_AVAILABLE = True
except ImportError:
    JINJA_AVAILABLE = False
    logger.warning("jinja2 not installed - HTML reports disabled")


# HTML report template
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Airdump Scan Report - {{ session_id }}</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
               line-height: 1.6; color: #333; background: #f5f5f5; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }
        header { background: #2c3e50; color: white; padding: 20px; margin-bottom: 20px; border-radius: 8px; }
        h1 { font-size: 1.8em; margin-bottom: 10px; }
        h2 { color: #2c3e50; margin: 20px 0 10px; border-bottom: 2px solid #3498db; padding-bottom: 5px; }
        h3 { color: #34495e; margin: 15px 0 10px; }
        .card { background: white; border-radius: 8px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; }
        .stat-box { background: #3498db; color: white; padding: 20px; border-radius: 8px; text-align: center; }
        .stat-box.warning { background: #e74c3c; }
        .stat-box.success { background: #27ae60; }
        .stat-value { font-size: 2.5em; font-weight: bold; }
        .stat-label { font-size: 0.9em; opacity: 0.9; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #34495e; color: white; }
        tr:hover { background: #f9f9f9; }
        .alert { padding: 15px; border-radius: 4px; margin: 10px 0; }
        .alert-danger { background: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }
        .alert-warning { background: #fff3cd; border: 1px solid #ffeeba; color: #856404; }
        .alert-info { background: #d1ecf1; border: 1px solid #bee5eb; color: #0c5460; }
        .mac { font-family: 'Courier New', monospace; font-size: 0.9em; }
        .badge { display: inline-block; padding: 3px 8px; border-radius: 4px; font-size: 0.8em; }
        .badge-unknown { background: #e74c3c; color: white; }
        .badge-known { background: #27ae60; color: white; }
        .badge-suspicious { background: #f39c12; color: white; }
        .map-container { height: 500px; border-radius: 8px; overflow: hidden; margin: 20px 0; }
        footer { text-align: center; color: #666; padding: 20px; font-size: 0.9em; }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🛸 Airdump Scan Report</h1>
            <p>Session: {{ session_id }}</p>
            <p>Generated: {{ generated_time }}</p>
        </header>
        
        <div class="card">
            <h2>📊 Summary Statistics</h2>
            <div class="stats">
                <div class="stat-box">
                    <div class="stat-value">{{ total_devices }}</div>
                    <div class="stat-label">Total Devices</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{{ wifi_devices }}</div>
                    <div class="stat-label">WiFi Devices</div>
                </div>
                <div class="stat-box">
                    <div class="stat-value">{{ bt_devices }}</div>
                    <div class="stat-label">Bluetooth Devices</div>
                </div>
                <div class="stat-box {% if unknown_devices > 0 %}warning{% else %}success{% endif %}">
                    <div class="stat-value">{{ unknown_devices }}</div>
                    <div class="stat-label">Unknown Devices</div>
                </div>
                <div class="stat-box {% if suspicious_devices > 0 %}warning{% else %}success{% endif %}">
                    <div class="stat-value">{{ suspicious_devices }}</div>
                    <div class="stat-label">Suspicious</div>
                </div>
            </div>
        </div>
        
        {% if alerts %}
        <div class="card">
            <h2>⚠️ Alerts</h2>
            {% for alert in alerts %}
            <div class="alert alert-danger">
                <strong>{{ alert.type }}:</strong> {{ alert.reason }}<br>
                <span class="mac">MAC: {{ alert.mac }}</span>
            </div>
            {% endfor %}
        </div>
        {% endif %}
        
        {% if unknown_wifi %}
        <div class="card">
            <h2>📡 Unknown WiFi Devices</h2>
            <table>
                <thead>
                    <tr>
                        <th>MAC Address</th>
                        <th>SSID</th>
                        <th>RSSI</th>
                        <th>Channel</th>
                        <th>First Seen</th>
                    </tr>
                </thead>
                <tbody>
                {% for device in unknown_wifi %}
                    <tr>
                        <td class="mac">{{ device.mac }}</td>
                        <td>{{ device.ssid or '-' }}</td>
                        <td>{{ device.rssi }} dBm</td>
                        <td>{{ device.channel }}</td>
                        <td>{{ device.first_seen }}</td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}
        
        {% if unknown_bt %}
        <div class="card">
            <h2>📶 Unknown Bluetooth Devices</h2>
            <table>
                <thead>
                    <tr>
                        <th>MAC Address</th>
                        <th>Name</th>
                        <th>Type</th>
                        <th>RSSI</th>
                        <th>First Seen</th>
                    </tr>
                </thead>
                <tbody>
                {% for device in unknown_bt %}
                    <tr>
                        <td class="mac">{{ device.mac }}</td>
                        <td>{{ device.name or '-' }}</td>
                        <td>{{ device.bt_type }}</td>
                        <td>{{ device.rssi }} dBm</td>
                        <td>{{ device.first_seen }}</td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}
        
        {% if suspicious %}
        <div class="card">
            <h2>🚨 Suspicious Devices</h2>
            <table>
                <thead>
                    <tr>
                        <th>MAC Address</th>
                        <th>Type</th>
                        <th>Reason</th>
                    </tr>
                </thead>
                <tbody>
                {% for device in suspicious %}
                    <tr>
                        <td class="mac">{{ device.mac }}</td>
                        <td>{{ device.device_type or 'unknown' }}</td>
                        <td>{{ device.suspicious_reason }}</td>
                    </tr>
                {% endfor %}
                </tbody>
            </table>
        </div>
        {% endif %}
        
        <div class="card">
            <h2>📍 Coverage Information</h2>
            <p><strong>GPS Track Points:</strong> {{ gps_track_points }}</p>
            <p><strong>Approximate Coverage Area:</strong> {{ coverage_area }} m²</p>
            {% if map_file %}
            <p><a href="{{ map_file }}">View Interactive Map</a></p>
            {% endif %}
        </div>
        
        <footer>
            <p>Generated by Project Airdump - Drone Wireless Reconnaissance System</p>
            <p>{{ generated_time }}</p>
        </footer>
    </div>
</body>
</html>
"""


class Reporter:
    """
    Generate reports from analysis results.
    
    Supports:
    - HTML reports with styling
    - Interactive maps (folium)
    - JSON export
    - CSV export
    """
    
    def __init__(
        self,
        output_dir: str = "data/reports",
        template_dir: Optional[str] = None,
    ):
        """
        Initialize reporter.
        
        Args:
            output_dir: Directory for output files
            template_dir: Custom template directory
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.template_dir = Path(template_dir) if template_dir else None
        
    def generate_html_report(
        self,
        analysis_result,
        output_file: Optional[str] = None,
        include_map: bool = True,
    ) -> str:
        """
        Generate HTML report from analysis result.
        
        Args:
            analysis_result: AnalysisResult object
            output_file: Output filename (auto-generated if None)
            include_map: Include interactive map
            
        Returns:
            Path to generated report
        """
        if not JINJA_AVAILABLE:
            logger.error("jinja2 required for HTML reports")
            return ""
            
        # Generate output filename
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"airdump_report_{analysis_result.session_id}_{timestamp}.html"
            
        output_path = self.output_dir / output_file
        
        # Generate map if requested
        map_file = None
        if include_map and FOLIUM_AVAILABLE:
            map_file = self.generate_map(
                analysis_result,
                output_file=output_file.replace('.html', '_map.html'),
            )
            
        # Render template
        template = Template(HTML_TEMPLATE)
        
        html_content = template.render(
            session_id=analysis_result.session_id,
            generated_time=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            total_devices=analysis_result.total_wifi_devices + analysis_result.total_bt_devices,
            wifi_devices=analysis_result.total_wifi_devices,
            bt_devices=analysis_result.total_bt_devices,
            unknown_devices=analysis_result.unknown_devices,
            suspicious_devices=analysis_result.suspicious_devices,
            alerts=analysis_result.alerts,
            unknown_wifi=analysis_result.unknown_wifi,
            unknown_bt=analysis_result.unknown_bt,
            suspicious=analysis_result.suspicious,
            gps_track_points=analysis_result.gps_track_points,
            coverage_area=f"{analysis_result.coverage_area_sqm:.1f}",
            map_file=map_file,
        )
        
        # Write file
        with open(output_path, 'w') as f:
            f.write(html_content)
            
        logger.info(f"Generated HTML report: {output_path}")
        return str(output_path)
        
    def generate_map(
        self,
        analysis_result,
        gps_track: List = None,
        output_file: Optional[str] = None,
    ) -> str:
        """
        Generate interactive map with device locations.
        
        Args:
            analysis_result: AnalysisResult object
            gps_track: Optional GPS track points
            output_file: Output filename
            
        Returns:
            Path to generated map
        """
        if not FOLIUM_AVAILABLE:
            logger.error("folium required for map generation")
            return ""
            
        # Collect all coordinates
        coords = []
        
        # From unknown WiFi devices
        for device in analysis_result.unknown_wifi:
            lat = device.get('latitude')
            lon = device.get('longitude')
            if lat and lon and lat != 0 and lon != 0:
                coords.append((lat, lon, 'wifi', device))
                
        # From unknown BT devices
        for device in analysis_result.unknown_bt:
            lat = device.get('latitude')
            lon = device.get('longitude')
            if lat and lon and lat != 0 and lon != 0:
                coords.append((lat, lon, 'bluetooth', device))
                
        # From suspicious devices
        for device in analysis_result.suspicious:
            lat = device.get('latitude')
            lon = device.get('longitude')
            if lat and lon and lat != 0 and lon != 0:
                coords.append((lat, lon, 'suspicious', device))
                
        if not coords:
            logger.warning("No GPS coordinates for map generation")
            return ""
            
        # Calculate center
        avg_lat = sum(c[0] for c in coords) / len(coords)
        avg_lon = sum(c[1] for c in coords) / len(coords)
        
        # Create map
        m = folium.Map(
            location=[avg_lat, avg_lon],
            zoom_start=17,
            tiles='OpenStreetMap',
        )
        
        # Add device markers
        for lat, lon, device_type, device in coords:
            # Choose marker color
            if device_type == 'suspicious':
                color = 'red'
                icon = 'exclamation-triangle'
            elif device_type == 'wifi':
                color = 'blue'
                icon = 'wifi'
            else:  # bluetooth
                color = 'purple'
                icon = 'bluetooth'
                
            # Create popup content
            popup_html = f"""
            <b>MAC:</b> {device.get('mac', 'Unknown')}<br>
            <b>Type:</b> {device_type}<br>
            <b>RSSI:</b> {device.get('rssi', 'N/A')} dBm<br>
            """
            
            if device.get('ssid'):
                popup_html += f"<b>SSID:</b> {device['ssid']}<br>"
            if device.get('name'):
                popup_html += f"<b>Name:</b> {device['name']}<br>"
            if device.get('suspicious_reason'):
                popup_html += f"<b>⚠️ Reason:</b> {device['suspicious_reason']}<br>"
                
            folium.Marker(
                location=[lat, lon],
                popup=folium.Popup(popup_html, max_width=300),
                icon=folium.Icon(color=color, icon=icon, prefix='fa'),
            ).add_to(m)
            
        # Add GPS track if provided
        if gps_track:
            track_coords = []
            for pos in gps_track:
                if hasattr(pos, 'latitude'):
                    track_coords.append([pos.latitude, pos.longitude])
                elif isinstance(pos, dict):
                    lat = pos.get('latitude', 0)
                    lon = pos.get('longitude', 0)
                    if lat and lon:
                        track_coords.append([lat, lon])
                        
            if track_coords:
                folium.PolyLine(
                    track_coords,
                    color='green',
                    weight=3,
                    opacity=0.7,
                ).add_to(m)
                
        # Generate output filename
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"airdump_map_{analysis_result.session_id}_{timestamp}.html"
            
        output_path = self.output_dir / output_file
        
        # Save map
        m.save(str(output_path))
        
        logger.info(f"Generated map: {output_path}")
        return str(output_path)
        
    def generate_json_report(
        self,
        analysis_result,
        output_file: Optional[str] = None,
        pretty: bool = True,
    ) -> str:
        """
        Generate JSON export of analysis results.
        
        Args:
            analysis_result: AnalysisResult object
            output_file: Output filename
            pretty: Pretty-print JSON
            
        Returns:
            Path to generated file
        """
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"airdump_report_{analysis_result.session_id}_{timestamp}.json"
            
        output_path = self.output_dir / output_file
        
        data = analysis_result.to_dict()
        
        with open(output_path, 'w') as f:
            if pretty:
                json.dump(data, f, indent=2, default=str)
            else:
                json.dump(data, f, default=str)
                
        logger.info(f"Generated JSON report: {output_path}")
        return str(output_path)
        
    def generate_csv_report(
        self,
        analysis_result,
        output_file: Optional[str] = None,
    ) -> str:
        """
        Generate CSV export of devices.
        
        Args:
            analysis_result: AnalysisResult object
            output_file: Output filename
            
        Returns:
            Path to generated file
        """
        import csv
        
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"airdump_devices_{analysis_result.session_id}_{timestamp}.csv"
            
        output_path = self.output_dir / output_file
        
        # Combine all devices
        all_devices = []
        
        for device in analysis_result.unknown_wifi:
            all_devices.append({
                "type": "wifi",
                "status": "unknown",
                **device,
            })
            
        for device in analysis_result.unknown_bt:
            all_devices.append({
                "type": "bluetooth",
                "status": "unknown",
                **device,
            })
            
        for device in analysis_result.suspicious:
            # Avoid duplicates
            existing = next(
                (d for d in all_devices if d.get('mac') == device.get('mac')),
                None
            )
            if existing:
                existing['status'] = 'suspicious'
                existing['suspicious_reason'] = device.get('suspicious_reason', '')
            else:
                all_devices.append({
                    "type": device.get('device_type', 'unknown'),
                    "status": "suspicious",
                    **device,
                })
                
        if not all_devices:
            logger.warning("No devices to export")
            return ""
            
        # Get all unique keys
        all_keys = set()
        for device in all_devices:
            all_keys.update(device.keys())
            
        # Write CSV
        fieldnames = sorted(all_keys)
        # Put important fields first
        priority_fields = ['mac', 'type', 'status', 'ssid', 'name', 'rssi', 'latitude', 'longitude']
        fieldnames = [f for f in priority_fields if f in fieldnames] + \
                     [f for f in fieldnames if f not in priority_fields]
                     
        with open(output_path, 'w', newline='') as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction='ignore')
            writer.writeheader()
            for device in all_devices:
                writer.writerow(device)
                
        logger.info(f"Generated CSV report: {output_path}")
        return str(output_path)
        
    def generate_all_reports(
        self,
        analysis_result,
        gps_track: List = None,
    ) -> Dict[str, str]:
        """
        Generate all report formats.
        
        Args:
            analysis_result: AnalysisResult object
            gps_track: Optional GPS track for map
            
        Returns:
            Dictionary of format -> filepath
        """
        reports = {}
        
        # HTML report
        html_path = self.generate_html_report(analysis_result)
        if html_path:
            reports['html'] = html_path
            
        # JSON report
        json_path = self.generate_json_report(analysis_result)
        if json_path:
            reports['json'] = json_path
            
        # CSV report
        csv_path = self.generate_csv_report(analysis_result)
        if csv_path:
            reports['csv'] = csv_path
            
        # Map
        if FOLIUM_AVAILABLE:
            map_path = self.generate_map(analysis_result, gps_track)
            if map_path:
                reports['map'] = map_path
                
        return reports


def generate_heatmap(
    devices: List[dict],
    output_file: str,
    radius: int = 25,
    blur: int = 15,
) -> str:
    """
    Generate heatmap of device locations.
    
    Args:
        devices: List of device dictionaries with lat/lon
        output_file: Output file path
        radius: Heatmap point radius
        blur: Heatmap blur amount
        
    Returns:
        Path to generated file
    """
    if not FOLIUM_AVAILABLE:
        logger.error("folium required for heatmap generation")
        return ""
        
    try:
        from folium.plugins import HeatMap
    except ImportError:
        logger.error("folium.plugins required for heatmap")
        return ""
        
    # Extract coordinates
    coords = []
    for device in devices:
        lat = device.get('latitude')
        lon = device.get('longitude')
        if lat and lon and lat != 0 and lon != 0:
            # Weight by RSSI (stronger signal = higher weight)
            rssi = device.get('rssi', -80)
            weight = max(0.1, (rssi + 100) / 100)  # Normalize to 0-1
            coords.append([lat, lon, weight])
            
    if not coords:
        logger.warning("No coordinates for heatmap")
        return ""
        
    # Calculate center
    avg_lat = sum(c[0] for c in coords) / len(coords)
    avg_lon = sum(c[1] for c in coords) / len(coords)
    
    # Create map with heatmap
    m = folium.Map(
        location=[avg_lat, avg_lon],
        zoom_start=17,
    )
    
    HeatMap(
        coords,
        radius=radius,
        blur=blur,
        max_zoom=18,
    ).add_to(m)
    
    # Save
    m.save(output_file)
    logger.info(f"Generated heatmap: {output_file}")
    
    return output_file


if __name__ == "__main__":
    import argparse
    import sys
    
    # Add parent directory to path for imports
    sys.path.insert(0, str(Path(__file__).parent.parent))
    
    from core.database import Database
    from analysis.analyzer import Analyzer
    
    parser = argparse.ArgumentParser(description="Generate scan reports")
    parser.add_argument("--session-id", required=True, help="Scan session ID")
    parser.add_argument("--database", default="/opt/airdump/data/database/airdump.db",
                        help="Database file path")
    parser.add_argument("--output-dir", default="/opt/airdump/data/reports",
                        help="Output directory for reports")
    parser.add_argument("--whitelist", help="Whitelist file for comparison")
    parser.add_argument("--format", choices=["html", "json", "csv", "map", "all"],
                        default="all", help="Report format")
    parser.add_argument("--all", action="store_true", help="Generate all report formats")
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(message)s"
    )
    
    # Initialize database
    db_path = Path(args.database)
    if not db_path.exists():
        print(f"Error: Database not found: {db_path}")
        sys.exit(1)
        
    db = Database(str(db_path))
    
    # Verify session exists
    session = db.get_session(args.session_id)
    if not session:
        print(f"Error: Session not found: {args.session_id}")
        print("\nAvailable sessions:")
        import sqlite3
        conn = sqlite3.connect(str(db_path))
        for row in conn.execute("SELECT session_id, start_time, status FROM scan_sessions ORDER BY id DESC LIMIT 10"):
            print(f"  {row[0]} - {row[1]} ({row[2]})")
        sys.exit(1)
    
    # Run analysis
    analyzer = Analyzer(database=db, whitelist_file=args.whitelist)
    analysis_result = analyzer.analyze_session(args.session_id)
    
    # Create output directory
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Generate reports
    reporter = Reporter(str(output_dir))
    
    if args.all or args.format == "all":
        reports = reporter.generate_all_reports(analysis_result)
        print(f"\nGenerated reports for session {args.session_id}:")
        for fmt, path in reports.items():
            print(f"  {fmt}: {path}")
    elif args.format == "html":
        path = reporter.generate_html_report(analysis_result)
        print(f"Generated HTML report: {path}")
    elif args.format == "json":
        path = reporter.generate_json_report(analysis_result)
        print(f"Generated JSON report: {path}")
    elif args.format == "csv":
        path = reporter.generate_csv_report(analysis_result)
        print(f"Generated CSV report: {path}")
    elif args.format == "map":
        path = reporter.generate_map(analysis_result)
        print(f"Generated map: {path}")
        
    # Print summary
    print(f"\nAnalysis Summary:")
    print(f"  Total WiFi devices: {analysis_result.total_wifi_devices}")
    print(f"  Total BT devices: {analysis_result.total_bt_devices}")
    print(f"  Unknown devices: {analysis_result.unknown_devices}")
    print(f"  Suspicious devices: {analysis_result.suspicious_devices}")
