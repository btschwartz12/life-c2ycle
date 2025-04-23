import ipaddress
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
import os
from typing import List

@dataclass
class Host:
    ip: str
    timestamp: str

def parse_hosts(ips: List[str], timestamps: List[str]) -> List[Host]:
    if len(ips) != len(timestamps):
        raise ValueError("ips and timestamps must be of the same length")

    hosts = []
    for ip, ts in zip(ips, timestamps):
        try:
            ipaddress.IPv4Address(ip)
        except ipaddress.AddressValueError:
            raise ValueError(f"Invalid IPv4 address: {ip}")
        try:
            datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            raise ValueError(f"Invalid RFC3339 timestamp: {ts}")

        hosts.append(Host(ip=ip, timestamp=ts))

    return hosts

def get_cache_filename(dir: str, host: Host) -> str:
    ip_part = host.ip.replace('.', '-')
    ts_part = ''.join(c for c in host.timestamp if c.isdigit())
    dirname = f"{dir}/{ip_part}"
    os.makedirs(dirname, exist_ok=True)
    return f"{dirname}/{ts_part}.json"

def get_plot_filename(malware: str, fname: str) -> str:
    fn = fname.replace('.', '-')
    dirname = f"paper/plots/{malware.lower()}"
    os.makedirs(dirname, exist_ok=True)
    return f"{dirname}/{fn}.png"

def get_agg_plot_filename(analytic: str) -> str:
    os.makedirs(f"paper/plots", exist_ok=True)
    return f"paper/plots/{analytic}.png"

def get_analysis_result_filename(c2_type: str, ioc_ip: str) -> str:
    d = f"paper/results"
    os.makedirs(d, exist_ok=True)
    return f"{d}/{c2_type}_{ioc_ip.replace('.', '-')}_analysis.json"

def get_time_ranges(timestamp: str, days_before: int, days_after: int, interval_min=None) -> List[str]:
    """Get a list of RFC3339 timestamps for the given range, excluding future times."""
    if days_before < 0 or days_after < 0:
        raise ValueError("days_before and days_after must be non-negative")
    if days_before == 0 and days_after == 0:
        return [timestamp]
    dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
    interval = timedelta(days=1)
    if interval_min:
        interval = timedelta(minutes=interval_min)
    now = datetime.now(timezone.utc)
    result = []
    start_time = dt - timedelta(days=days_before)
    end_time = min(dt + timedelta(days=days_after), now)
    current_time = start_time
    while current_time <= end_time:
        rfc3339 = current_time.isoformat().replace('+00:00', 'Z')
        result.append(rfc3339)
        current_time += interval
    return result
