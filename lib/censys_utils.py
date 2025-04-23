from dataclasses import dataclass, field
import json
import os
from typing import Dict, List, Optional
from censys.search import CensysHosts
from rich import print
from dotenv import load_dotenv
import lib.utils as utils

load_dotenv()

CENSYS_API_ID = os.getenv("CENSYS_API_ID")
CENSYS_API_SECRET = os.getenv("CENSYS_API_SECRET")

# print(f"[gray69]Censys API ID: {CENSYS_API_ID}[/gray69]")
# print(f"[gray69]Censys API Secret: {CENSYS_API_SECRET}[/gray69]")

if not CENSYS_API_ID or not CENSYS_API_SECRET:
    raise ValueError("Missing Censys API credentials.")

censys_client = CensysHosts(api_id=CENSYS_API_ID, api_secret=CENSYS_API_SECRET)

@dataclass
class Software:
    product: str = ""
    is_c2_device: bool = False

@dataclass
class TLSData:
    tls_version: str = ""
    cipher_selected: str = ""
    leaf_fingerprint: str = ""
    leaf_subject_dn: str = ""
    leaf_issuer_dn: str = ""
    leaf_pubkey_algorithm: str = ""
    leaf_tbs_fingerprint: str = ""
    leaf_data_fingerprint: str = ""
    leaf_pubkey_fingerprint: str = ""

@dataclass
class ASData:
    asn: int
    description: str
    bgp_prefix: str
    name: str
    country_code: str
    updated_at: str

@dataclass
class OSData:
    vendor: str = ""
    product: str = ""

@dataclass
class SSHData:
    banner: str = ""
    banner_hashes: List[str] = field(default_factory=list)
    labels: List[str] = field(default_factory=list)
    port: int = 0
    version: str = ""
    comment: str = ""
    host_key_algorithm: str = ""
    server_host_key_fingerprint: str = ""

@dataclass
class RDPData:
    labels: List[str] = field(default_factory=list)
    port: int = 0
    certificate: str = ""

@dataclass
class LocationData:
    country: str = ""
    country_code: str = ""

@dataclass
class DNSData:
    names: List[str] = field(default_factory=list)

@dataclass
class Service:
    observed_at: str = ""
    labels: List[str] = field(default_factory=list)
    port: int = 0
    transport_protocol: str = ""
    software: List[Software] = field(default_factory=list)
    tls: Optional[TLSData] = None
    has_c2_label: bool = False
    has_c2_software: bool = False

Port = int
Services = Dict[Port, Service]

@dataclass
class CensysHost:
    ip: str = ""
    query_timestamp: str = ""
    last_updated_at: str = ""
    labels: List[str] = field(default_factory=list)

    # host-specific
    os_data: OSData = None
    as_data: ASData = None
    location_data: LocationData = None
    dns_data: DNSData = None

    # service-specific
    ssh_data: List[SSHData] = field(default_factory=list)
    rdp_data: List[RDPData] = field(default_factory=list)
    services: Services = field(default_factory=dict)
    
def parse_service(raw_service_data: dict) -> Service:
    """Parse raw service data from Censys into a Service object."""
    service = Service()
    service.observed_at = raw_service_data.get("observed_at", "")
    service.labels = raw_service_data.get("labels", [])
    service.has_c2_label = "c2" in service.labels
    service.port = raw_service_data.get("port", 0)
    service.transport_protocol = raw_service_data.get("transport_protocol", "")
    # parse software data
    softwares = []
    for s in raw_service_data.get("software", []):
        softwares.append(Software(s.get("product", ""), s.get("other", {}).get("device", "") == "c2"))
    service.software = softwares
    service.has_c2_software = any(s.is_c2_device for s in service.software)
    # parse tls data
    tls = raw_service_data.get("tls", None)
    if tls:
        tls_data = TLSData(
            tls_version=tls.get("version_selected", ""),
            cipher_selected=tls.get("cipher_selected", ""),
        )
        # parse certificate data
        certificates = tls.get("certificates", None)
        if certificates:
            tls_data.leaf_fingerprint = certificates.get("leaf_fp_sha_256", "")
            leaf_data = certificates.get("leaf_data", None)
            if leaf_data:
                tls_data.leaf_data_fingerprint = leaf_data.get("fingerprint", "")
                tls_data.leaf_subject_dn = leaf_data.get("subject_dn", "")
                tls_data.leaf_issuer_dn = leaf_data.get("issuer_dn", "")
                tls_data.leaf_pubkey_algorithm = leaf_data.get("pubkey_algorithm", "")
                tls_data.leaf_tbs_fingerprint = leaf_data.get("tbs_fingerprint", "")
                # parse pubkey data
                pubkey = leaf_data.get("pubkey", None)
                if pubkey:
                    tls_data.leaf_pubkey_fingerprint = pubkey.get("fingerprint", "")
        service.tls = tls_data
    return service

def parse_ssh_data(raw_host_data: dict) -> List[SSHData]:
    data = []
    for s in raw_host_data.get("services", []):
        if s.get("service_name", "") == "SSH":
            ssh_data = s.get("ssh", None)
            if not ssh_data:
                continue
            data.append(SSHData(
                banner=s.get("banner", ""),
                banner_hashes=s.get("banner_hashes", []),
                labels=s.get("labels", []),
                port=s.get("port", 0),
                version=ssh_data.get("endpoint_id", {}).get("software_version", ""),
                comment=ssh_data.get("endpoint_id", {}).get("comment", ""),
                host_key_algorithm=ssh_data.get("algorithm_selection", {}).get("host_key_algorithm", ""),
                server_host_key_fingerprint=ssh_data.get("server_host_key", {}).get("fingerprint_sha256", ""),
            ))
    return data

def parse_rdp_data(raw_host_data: dict) -> List[RDPData]:
    data = []
    for s in raw_host_data.get("services", []):
        if s.get("service_name", "") == "RDP":
            data.append(RDPData(
                labels=s.get("labels", []),
                port=s.get("port", 0),
                certificate=s.get("certificate", ""),
            ))
    return data

def parse_location_data(raw_host_data: dict) -> LocationData:
    return LocationData(
        country=raw_host_data.get("location", {}).get("country", ""),
        country_code=raw_host_data.get("location", {}).get("country_code", ""),
    )

def parse_dns_data(raw_host_data: dict) -> DNSData:
    return DNSData(
        names=raw_host_data.get("dns", {}).get("names", []),
    )

def parse_as_data(raw_host_data: dict) -> ASData:
    return ASData(
        asn=raw_host_data.get("autonomous_system", {}).get("asn", 0),
        description=raw_host_data.get("autonomous_system", {}).get("description", ""),
        bgp_prefix=raw_host_data.get("autonomous_system", {}).get("bgp_prefix", ""),
        name=raw_host_data.get("autonomous_system", {}).get("name", ""),
        country_code=raw_host_data.get("autonomous_system", {}).get("country_code", ""),
        updated_at=raw_host_data.get("autonomous_system_updated_at", ""),
    ) 

def parse_os_data(raw_host_data: dict) -> OSData:
    return OSData(
        vendor=raw_host_data.get("operating_system", {}).get("vendor", ""),
        product=raw_host_data.get("operating_system", {}).get("product", ""),
    )

def parse_host_view(raw_host_data: dict, query_timestamp: str) -> CensysHost:

    return CensysHost(
        ip=raw_host_data.get("ip", ""),
        query_timestamp=query_timestamp,
        labels=raw_host_data.get("labels", []),
        last_updated_at=raw_host_data.get("last_updated_at", ""),

        as_data=parse_as_data(raw_host_data),
        os_data=parse_os_data(raw_host_data),
        dns_data=parse_dns_data(raw_host_data),
        ssh_data=parse_ssh_data(raw_host_data),
        rdp_data=parse_rdp_data(raw_host_data),
        location_data=parse_location_data(raw_host_data),
        
        services={s["port"]: parse_service(s) for s in raw_host_data.get("services", [])}
    )
   
def fetch_censys_host(host: utils.Host) -> CensysHost:
    cache_filename = utils.get_cache_filename("censys_cache", host)
    if os.path.exists(cache_filename):
        with open(cache_filename, 'r') as f:
            raw_host_data = json.load(f)
        print(f"[gray69]Found cached host data for {host.ip} at {host.timestamp}[/gray69]")
        return parse_host_view(raw_host_data, host.timestamp)
    
    try:
        print(f"[gray69]Fetching host data for {host.ip} at {host.timestamp}...[/gray69]")
        raw_host_data = censys_client.view(host.ip, at_time=host.timestamp)
        with open(cache_filename, 'w') as f:
            json.dump(raw_host_data, f, indent=4)
        print(f"[gray69]Cached data for {host.ip} at {host.timestamp}[/gray69]")
        return parse_host_view(raw_host_data, host.timestamp)
    except Exception as e:
        raise RuntimeError(f"Failed to retrieve host data: {e}")

@dataclass
class LookAroundResult:
    """
    The results of 'looking around' a certain IP and timestamp,
    including all of the parsed data.
    """
    ip: str
    ioc_timestamp: str
    days_before: int
    days_after: int
    scanned_timestamps: List[str] = field(default_factory=list)
    # dict of timestamp -> CensysHost, ordered ascending
    data: Dict[str, CensysHost] = field(default_factory=dict)

def look_around(host: utils.Host, days_before: int, days_after: int) -> LookAroundResult:
    """
    Look around a certain IP and timestamp, fetching data for the specified
    number of days before and after the given timestamp.
    """
    timestamps = utils.get_time_ranges(host.timestamp, days_before, days_after)
    result = LookAroundResult(ip=host.ip, ioc_timestamp=host.timestamp, days_before=days_before, days_after=days_after, scanned_timestamps=timestamps)
    for ts in timestamps:
        try:
            censys_host = fetch_censys_host(utils.Host(ip=host.ip, timestamp=ts))
            result.data[ts] = censys_host
        except Exception as e:
            print(f"[red]Error fetching data for {host.ip} at {ts}: {e}[/red]")
    return result

