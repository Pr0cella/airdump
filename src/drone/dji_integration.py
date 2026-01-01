"""
Project Airdump - DJI Integration

Parse DJI flight logs for:
- High-precision GPS track
- Photo correlation with detections
- Flight metadata
"""

import logging
import json
import csv
from pathlib import Path
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class DJIGPSPoint:
    """GPS point from DJI flight log."""
    
    timestamp: datetime
    latitude: float
    longitude: float
    altitude: float  # meters above sea level
    height: float  # meters above takeoff point
    speed: float  # m/s
    heading: float  # degrees
    
    # Additional telemetry
    satellites: int = 0
    gps_signal: int = 0
    battery_percent: int = 100
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "latitude": self.latitude,
            "longitude": self.longitude,
            "altitude": self.altitude,
            "height": self.height,
            "speed": self.speed,
            "heading": self.heading,
            "satellites": self.satellites,
            "gps_signal": self.gps_signal,
            "battery_percent": self.battery_percent,
        }


@dataclass
class DJIPhoto:
    """Photo metadata from DJI flight."""
    
    filename: str
    timestamp: datetime
    latitude: float
    longitude: float
    altitude: float
    
    # Camera settings
    iso: int = 0
    shutter_speed: str = ""
    aperture: float = 0.0
    focal_length: float = 0.0
    
    # Gimbal
    gimbal_pitch: float = 0.0
    gimbal_yaw: float = 0.0
    gimbal_roll: float = 0.0
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "filename": self.filename,
            "timestamp": self.timestamp.isoformat(),
            "latitude": self.latitude,
            "longitude": self.longitude,
            "altitude": self.altitude,
            "iso": self.iso,
            "shutter_speed": self.shutter_speed,
            "aperture": self.aperture,
            "focal_length": self.focal_length,
            "gimbal_pitch": self.gimbal_pitch,
            "gimbal_yaw": self.gimbal_yaw,
            "gimbal_roll": self.gimbal_roll,
        }


@dataclass
class DJIFlight:
    """Complete DJI flight record."""
    
    flight_id: str
    start_time: datetime
    end_time: Optional[datetime] = None
    
    # Location
    takeoff_lat: float = 0.0
    takeoff_lon: float = 0.0
    
    # Stats
    max_altitude: float = 0.0
    max_speed: float = 0.0
    distance: float = 0.0  # Total distance in meters
    
    # Aircraft info
    aircraft_model: str = ""
    aircraft_serial: str = ""
    
    # Track and photos
    gps_track: List[DJIGPSPoint] = field(default_factory=list)
    photos: List[DJIPhoto] = field(default_factory=list)
    
    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return {
            "flight_id": self.flight_id,
            "start_time": self.start_time.isoformat(),
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "takeoff_lat": self.takeoff_lat,
            "takeoff_lon": self.takeoff_lon,
            "max_altitude": self.max_altitude,
            "max_speed": self.max_speed,
            "distance": self.distance,
            "aircraft_model": self.aircraft_model,
            "aircraft_serial": self.aircraft_serial,
            "track_points": len(self.gps_track),
            "photo_count": len(self.photos),
        }


class DJILogParser:
    """
    Parse DJI flight logs.
    
    Supports:
    - DJI TXT logs (from DJI Assistant)
    - CSV exports from various tools
    - DAT binary logs (with external conversion)
    """
    
    def __init__(self):
        """Initialize DJI log parser."""
        self._flights: Dict[str, DJIFlight] = {}
        
    def parse_txt_log(self, filepath: str) -> Optional[DJIFlight]:
        """
        Parse DJI TXT format log.
        
        Args:
            filepath: Path to TXT log file
            
        Returns:
            DJIFlight object or None
        """
        path = Path(filepath)
        if not path.exists():
            logger.error(f"Log file not found: {filepath}")
            return None
            
        try:
            flight = DJIFlight(
                flight_id=path.stem,
                start_time=datetime.utcnow(),  # Will be updated
            )
            
            with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
                
            # Parse header info
            for line in lines[:50]:
                if "Aircraft" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        flight.aircraft_model = parts[1].strip()
                elif "Serial" in line:
                    parts = line.split(":")
                    if len(parts) >= 2:
                        flight.aircraft_serial = parts[1].strip()
                        
            # Parse GPS data (format varies by DJI version)
            # This is a simplified parser - real implementation would
            # handle multiple log formats
            
            for line in lines:
                try:
                    # Look for GPS coordinate lines
                    if "GPS" in line and "Lat" in line:
                        # Parse coordinates from line
                        gps_point = self._parse_gps_line(line)
                        if gps_point:
                            flight.gps_track.append(gps_point)
                except Exception:
                    continue
                    
            # Update flight stats
            if flight.gps_track:
                flight.start_time = flight.gps_track[0].timestamp
                flight.end_time = flight.gps_track[-1].timestamp
                flight.takeoff_lat = flight.gps_track[0].latitude
                flight.takeoff_lon = flight.gps_track[0].longitude
                flight.max_altitude = max(p.altitude for p in flight.gps_track)
                flight.max_speed = max(p.speed for p in flight.gps_track)
                flight.distance = self._calculate_distance(flight.gps_track)
                
            self._flights[flight.flight_id] = flight
            logger.info(f"Parsed flight {flight.flight_id}: {len(flight.gps_track)} GPS points")
            return flight
            
        except Exception as e:
            logger.error(f"Failed to parse log: {e}")
            return None
            
    def parse_csv_log(self, filepath: str) -> Optional[DJIFlight]:
        """
        Parse CSV format flight log.
        
        Args:
            filepath: Path to CSV log file
            
        Returns:
            DJIFlight object or None
        """
        path = Path(filepath)
        if not path.exists():
            logger.error(f"CSV file not found: {filepath}")
            return None
            
        try:
            flight = DJIFlight(
                flight_id=path.stem,
                start_time=datetime.utcnow(),
            )
            
            with open(path, 'r', newline='') as f:
                reader = csv.DictReader(f)
                
                for row in reader:
                    try:
                        # Try to parse GPS point from row
                        gps_point = self._parse_csv_row(row)
                        if gps_point:
                            flight.gps_track.append(gps_point)
                    except Exception:
                        continue
                        
            # Update flight stats
            if flight.gps_track:
                flight.start_time = flight.gps_track[0].timestamp
                flight.end_time = flight.gps_track[-1].timestamp
                flight.takeoff_lat = flight.gps_track[0].latitude
                flight.takeoff_lon = flight.gps_track[0].longitude
                flight.max_altitude = max(p.altitude for p in flight.gps_track)
                flight.max_speed = max(p.speed for p in flight.gps_track)
                flight.distance = self._calculate_distance(flight.gps_track)
                
            self._flights[flight.flight_id] = flight
            logger.info(f"Parsed CSV flight {flight.flight_id}: {len(flight.gps_track)} GPS points")
            return flight
            
        except Exception as e:
            logger.error(f"Failed to parse CSV: {e}")
            return None
            
    def _parse_gps_line(self, line: str) -> Optional[DJIGPSPoint]:
        """Parse GPS point from log line (format-dependent)."""
        # This is a placeholder - actual implementation would
        # handle specific DJI log formats
        return None
        
    def _parse_csv_row(self, row: dict) -> Optional[DJIGPSPoint]:
        """Parse GPS point from CSV row."""
        try:
            # Try common column names
            lat = float(row.get('latitude', row.get('Latitude', row.get('GPS_Lat', 0))))
            lon = float(row.get('longitude', row.get('Longitude', row.get('GPS_Lon', 0))))
            
            if lat == 0 and lon == 0:
                return None
                
            # Parse timestamp
            ts_str = row.get('timestamp', row.get('Timestamp', row.get('time', '')))
            if ts_str:
                try:
                    timestamp = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
                except:
                    timestamp = datetime.utcnow()
            else:
                timestamp = datetime.utcnow()
                
            return DJIGPSPoint(
                timestamp=timestamp,
                latitude=lat,
                longitude=lon,
                altitude=float(row.get('altitude', row.get('Altitude', 0))),
                height=float(row.get('height', row.get('Height', 0))),
                speed=float(row.get('speed', row.get('Speed', 0))),
                heading=float(row.get('heading', row.get('Heading', 0))),
                satellites=int(row.get('satellites', row.get('GPS_Sats', 0))),
                battery_percent=int(row.get('battery', row.get('Battery', 100))),
            )
            
        except Exception:
            return None
            
    def _calculate_distance(self, track: List[DJIGPSPoint]) -> float:
        """Calculate total distance from GPS track."""
        if len(track) < 2:
            return 0.0
            
        import math
        
        def haversine(lat1, lon1, lat2, lon2):
            R = 6371000  # Earth radius in meters
            phi1 = math.radians(lat1)
            phi2 = math.radians(lat2)
            delta_phi = math.radians(lat2 - lat1)
            delta_lambda = math.radians(lon2 - lon1)
            
            a = math.sin(delta_phi/2)**2 + \
                math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda/2)**2
            c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
            
            return R * c
            
        total = 0.0
        for i in range(1, len(track)):
            total += haversine(
                track[i-1].latitude, track[i-1].longitude,
                track[i].latitude, track[i].longitude
            )
            
        return total
        
    def get_position_at_time(
        self,
        flight_id: str,
        timestamp: datetime,
    ) -> Optional[Tuple[float, float, float]]:
        """
        Get interpolated GPS position at specific time.
        
        Args:
            flight_id: Flight ID
            timestamp: Time to query
            
        Returns:
            (latitude, longitude, altitude) tuple or None
        """
        flight = self._flights.get(flight_id)
        if not flight or not flight.gps_track:
            return None
            
        track = flight.gps_track
        
        # Find bracketing points
        for i, point in enumerate(track):
            if point.timestamp >= timestamp:
                if i == 0:
                    return (point.latitude, point.longitude, point.altitude)
                    
                # Interpolate between points
                prev = track[i - 1]
                total_time = (point.timestamp - prev.timestamp).total_seconds()
                elapsed = (timestamp - prev.timestamp).total_seconds()
                
                if total_time <= 0:
                    return (point.latitude, point.longitude, point.altitude)
                    
                ratio = elapsed / total_time
                
                lat = prev.latitude + ratio * (point.latitude - prev.latitude)
                lon = prev.longitude + ratio * (point.longitude - prev.longitude)
                alt = prev.altitude + ratio * (point.altitude - prev.altitude)
                
                return (lat, lon, alt)
                
        # After end of track
        return (track[-1].latitude, track[-1].longitude, track[-1].altitude)
        
    def upgrade_device_gps(
        self,
        device: dict,
        flight_id: str,
        time_tolerance_sec: float = 5.0,
    ) -> dict:
        """
        Upgrade device GPS from DJI track (higher precision).
        
        Args:
            device: Device dictionary with timestamp
            flight_id: Flight ID for GPS track
            time_tolerance_sec: Max time difference to accept
            
        Returns:
            Device with upgraded GPS
        """
        device = device.copy()
        
        # Get device timestamp
        ts_str = device.get('first_seen', device.get('timestamp', device.get('last_seen')))
        if not ts_str:
            return device
            
        try:
            if isinstance(ts_str, str):
                timestamp = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
            else:
                timestamp = ts_str
        except:
            return device
            
        # Get DJI position
        pos = self.get_position_at_time(flight_id, timestamp)
        if pos:
            device['latitude'] = pos[0]
            device['longitude'] = pos[1]
            device['altitude'] = pos[2]
            device['gps_source'] = 'dji'
            device['gps_upgraded'] = True
            
        return device
        
    def correlate_photos(
        self,
        flight_id: str,
        photo_dir: str,
    ) -> List[DJIPhoto]:
        """
        Correlate photos with GPS positions.
        
        Args:
            flight_id: Flight ID
            photo_dir: Directory containing photos
            
        Returns:
            List of DJIPhoto objects with GPS data
        """
        photos = []
        photo_path = Path(photo_dir)
        
        if not photo_path.exists():
            return photos
            
        flight = self._flights.get(flight_id)
        if not flight:
            return photos
            
        # Process image files
        for img_file in photo_path.glob("*.{jpg,JPG,jpeg,JPEG,dng,DNG}"):
            try:
                photo = self._parse_photo(img_file, flight)
                if photo:
                    photos.append(photo)
            except Exception as e:
                logger.debug(f"Failed to parse photo {img_file}: {e}")
                
        return photos
        
    def _parse_photo(
        self,
        filepath: Path,
        flight: DJIFlight,
    ) -> Optional[DJIPhoto]:
        """Parse photo metadata and correlate with flight."""
        try:
            # Try to read EXIF data
            from PIL import Image
            from PIL.ExifTags import TAGS, GPSTAGS
            
            img = Image.open(filepath)
            exif = img._getexif()
            
            if not exif:
                return None
                
            # Extract timestamp
            timestamp = None
            for tag_id, value in exif.items():
                tag = TAGS.get(tag_id, tag_id)
                if tag == "DateTimeOriginal":
                    timestamp = datetime.strptime(value, "%Y:%m:%d %H:%M:%S")
                    break
                    
            if not timestamp:
                return None
                
            # Get GPS from EXIF or interpolate from flight
            lat, lon, alt = 0.0, 0.0, 0.0
            
            # Try EXIF GPS first
            gps_info = {}
            for tag_id, value in exif.items():
                tag = TAGS.get(tag_id, tag_id)
                if tag == "GPSInfo":
                    for gps_tag_id, gps_value in value.items():
                        gps_tag = GPSTAGS.get(gps_tag_id, gps_tag_id)
                        gps_info[gps_tag] = gps_value
                        
            if gps_info:
                # Parse EXIF GPS
                if 'GPSLatitude' in gps_info and 'GPSLongitude' in gps_info:
                    lat = self._convert_gps_coords(
                        gps_info['GPSLatitude'],
                        gps_info.get('GPSLatitudeRef', 'N')
                    )
                    lon = self._convert_gps_coords(
                        gps_info['GPSLongitude'],
                        gps_info.get('GPSLongitudeRef', 'E')
                    )
                if 'GPSAltitude' in gps_info:
                    alt = float(gps_info['GPSAltitude'])
            else:
                # Interpolate from flight track
                pos = self.get_position_at_time(flight.flight_id, timestamp)
                if pos:
                    lat, lon, alt = pos
                    
            return DJIPhoto(
                filename=filepath.name,
                timestamp=timestamp,
                latitude=lat,
                longitude=lon,
                altitude=alt,
            )
            
        except ImportError:
            logger.debug("PIL not available for photo parsing")
            return None
        except Exception as e:
            logger.debug(f"Photo parse error: {e}")
            return None
            
    def _convert_gps_coords(self, coords: tuple, ref: str) -> float:
        """Convert EXIF GPS coordinates to decimal degrees."""
        try:
            degrees = float(coords[0])
            minutes = float(coords[1])
            seconds = float(coords[2])
            
            decimal = degrees + minutes/60 + seconds/3600
            
            if ref in ['S', 'W']:
                decimal = -decimal
                
            return decimal
        except:
            return 0.0
            
    def export_gpx(self, flight_id: str, output_file: str) -> bool:
        """
        Export flight track as GPX file.
        
        Args:
            flight_id: Flight ID
            output_file: Output GPX file path
            
        Returns:
            True if successful
        """
        flight = self._flights.get(flight_id)
        if not flight or not flight.gps_track:
            return False
            
        gpx_template = '''<?xml version="1.0" encoding="UTF-8"?>
<gpx version="1.1" creator="Airdump">
  <metadata>
    <name>{name}</name>
    <time>{time}</time>
  </metadata>
  <trk>
    <name>{name}</name>
    <trkseg>
{points}
    </trkseg>
  </trk>
</gpx>'''
        
        points_xml = []
        for point in flight.gps_track:
            points_xml.append(
                f'      <trkpt lat="{point.latitude}" lon="{point.longitude}">\n'
                f'        <ele>{point.altitude}</ele>\n'
                f'        <time>{point.timestamp.isoformat()}Z</time>\n'
                f'      </trkpt>'
            )
            
        gpx_content = gpx_template.format(
            name=flight_id,
            time=flight.start_time.isoformat() + 'Z',
            points='\n'.join(points_xml),
        )
        
        try:
            with open(output_file, 'w') as f:
                f.write(gpx_content)
            logger.info(f"Exported GPX: {output_file}")
            return True
        except Exception as e:
            logger.error(f"GPX export failed: {e}")
            return False
            
    def get_flight(self, flight_id: str) -> Optional[DJIFlight]:
        """Get flight by ID."""
        return self._flights.get(flight_id)
        
    def list_flights(self) -> List[str]:
        """List all parsed flight IDs."""
        return list(self._flights.keys())
