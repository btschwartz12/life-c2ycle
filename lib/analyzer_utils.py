import json
import lib.censys_utils as censys_utils
from typing import List, Dict
from dataclasses import asdict, dataclass, field



@dataclass
class ASAnalysis:
    ioc_data: censys_utils.ASData = None
    # timestamp -> data
    observed_asn: Dict[str, int] = field(default_factory=dict)
    observed_description: Dict[str, str] = field(default_factory=dict)
    observed_bgp_prefix: Dict[str, str] = field(default_factory=dict)
    observed_name: Dict[str, str] = field(default_factory=dict)
    observed_country_code: Dict[str, str] = field(default_factory=dict)
    observed_updated_at: Dict[str, str] = field(default_factory=dict)

def build_as_analysis(look_around_result: censys_utils.LookAroundResult) -> ASAnalysis:
    ioc_host = look_around_result.data.get(look_around_result.ioc_timestamp)
    res = ASAnalysis(ioc_data=ioc_host.as_data)
    for ts in look_around_result.scanned_timestamps:
        res.observed_asn[ts] = None
        res.observed_description[ts] = None
        res.observed_bgp_prefix[ts] = None
        res.observed_name[ts] = None
        res.observed_country_code[ts] = None
        res.observed_updated_at[ts] = None
    for ts in sorted(look_around_result.data.keys()):
        host = look_around_result.data[ts]
        if host.as_data:
            res.observed_asn[ts] = host.as_data.asn
            res.observed_description[ts] = host.as_data.description
            res.observed_bgp_prefix[ts] = host.as_data.bgp_prefix
            res.observed_name[ts] = host.as_data.name
            res.observed_country_code[ts] = host.as_data.country_code
            res.observed_updated_at[ts] = host.as_data.updated_at
    return res

@dataclass
class OSAnalysis:
    ioc_data: censys_utils.OSData = None
    # timestamp -> data
    observed_vendor: Dict[str, str] = field(default_factory=dict)
    observed_product: Dict[str, str] = field(default_factory=dict)

def build_os_analysis(look_around_result: censys_utils.LookAroundResult) -> OSAnalysis:
    ioc_host = look_around_result.data.get(look_around_result.ioc_timestamp)
    res = OSAnalysis(ioc_data=ioc_host.os_data)
    for ts in look_around_result.scanned_timestamps:
        res.observed_vendor[ts] = None
        res.observed_product[ts] = None
    for ts in sorted(look_around_result.data.keys()):
        host = look_around_result.data[ts]
        if host.os_data:
            res.observed_vendor[ts] = host.os_data.vendor
            res.observed_product[ts] = host.os_data.product
    return res

@dataclass
class SSHAnalysis:
    ioc_data: List[censys_utils.SSHData] = None
    # timestamp -> port -> data
    observed_banners: Dict[str, Dict[int, str]] = field(default_factory=dict)
    observed_banners_hashes: Dict[str, Dict[int, List[str]]] = field(default_factory=dict)
    observed_labels: Dict[str, Dict[int, List[str]]] = field(default_factory=dict)
    observed_version: Dict[str, Dict[int, str]] = field(default_factory=dict)
    observed_comment: Dict[str, Dict[int, str]] = field(default_factory=dict)
    observed_host_key_algorithm: Dict[str, Dict[int, str]] = field(default_factory=dict)
    observed_server_host_key_fingerprint: Dict[str, Dict[int, str]] = field(default_factory=dict)

def build_ssh_analysis(look_around_result: censys_utils.LookAroundResult) -> SSHAnalysis:
    ioc_host = look_around_result.data.get(look_around_result.ioc_timestamp)
    res = SSHAnalysis(ioc_data=ioc_host.ssh_data)
    for ts in look_around_result.scanned_timestamps:
        res.observed_banners[ts] = {}
        res.observed_banners_hashes[ts] = {}
        res.observed_labels[ts] = {}
        res.observed_version[ts] = {}
        res.observed_comment[ts] = {}
        res.observed_host_key_algorithm[ts] = {}
        res.observed_server_host_key_fingerprint[ts] = {}
    for ts in sorted(look_around_result.data.keys()):
        host = look_around_result.data[ts]
        if not host.ssh_data:
            continue
        for ssh in host.ssh_data:
            port = ssh.port
            res.observed_banners[ts][port] = ssh.banner
            res.observed_banners_hashes[ts][port] = ssh.banner_hashes
            res.observed_labels[ts][port] = ssh.labels
            res.observed_version[ts][port] = ssh.version
            res.observed_comment[ts][port] = ssh.comment
            res.observed_host_key_algorithm[ts][port] = ssh.host_key_algorithm
            res.observed_server_host_key_fingerprint[ts][port] = ssh.server_host_key_fingerprint
    return res

@dataclass
class RDPAnalysis:
    ioc_data: List[censys_utils.RDPData] = None
    # timestamp -> port -> data
    observed_labels: Dict[str, Dict[int, List[str]]] = field(default_factory=dict)
    observed_certificate: Dict[str, Dict[int, str]] = field(default_factory=dict)                                                                                                                                               

def build_rdp_analysis(look_around_result: censys_utils.LookAroundResult) -> RDPAnalysis:
    ioc_host = look_around_result.data.get(look_around_result.ioc_timestamp)
    res = RDPAnalysis(ioc_data=ioc_host.rdp_data)
    for ts in look_around_result.scanned_timestamps:
        res.observed_labels[ts] = {}
        res.observed_certificate[ts] = {}
    for ts in sorted(look_around_result.data.keys()):
        host = look_around_result.data[ts]
        if not host.rdp_data:
            continue
        for rdp in host.rdp_data:
            port = rdp.port
            res.observed_labels[ts][port] = rdp.labels
            res.observed_certificate[ts][port] = rdp.certificate
    return res

@dataclass
class LocationAnalysis:
    ioc_data: censys_utils.LocationData = None
    # timestamp -> data
    observed_country: Dict[str, str] = field(default_factory=dict)
    observed_country_code: Dict[str, str] = field(default_factory=dict)

def build_location_analysis(look_around_result: censys_utils.LookAroundResult) -> LocationAnalysis:
    ioc_host = look_around_result.data.get(look_around_result.ioc_timestamp)
    res = LocationAnalysis(ioc_data=ioc_host.location_data)
    for ts in look_around_result.scanned_timestamps:
        res.observed_country[ts] = None
        res.observed_country_code[ts] = None
    for ts in sorted(look_around_result.data.keys()):
        host = look_around_result.data[ts]
        if host.location_data:
            res.observed_country[ts] = host.location_data.country
            res.observed_country_code[ts] = host.location_data.country_code
    return res

@dataclass
class DNSAnalysis:
    ioc_data: censys_utils.DNSData = None
    # timestamp -> data
    observed_names: Dict[str, List[str]] = field(default_factory=dict)

def build_dns_analysis(look_around_result: censys_utils.LookAroundResult) -> DNSAnalysis:
    ioc_host = look_around_result.data.get(look_around_result.ioc_timestamp)
    res = DNSAnalysis(ioc_data=ioc_host.dns_data)
    for ts in look_around_result.scanned_timestamps:
        res.observed_names[ts] = []
    for ts in sorted(look_around_result.data.keys()):
        host = look_around_result.data[ts]
        if host.dns_data:
            res.observed_names[ts] = host.dns_data.names
    return res

@dataclass
class LabelsAnalysis:
    ioc_data: List[str] = field(default_factory=list)
    # timestamp -> data
    observed_labels: Dict[str, List[str]] = field(default_factory=dict)

def build_labels_analysis(look_around_result: censys_utils.LookAroundResult) -> LabelsAnalysis:
    ioc_host = look_around_result.data.get(look_around_result.ioc_timestamp)
    res = LabelsAnalysis(ioc_data=ioc_host.labels)
    for ts in look_around_result.scanned_timestamps:
        res.observed_labels[ts] = []
    for ts in sorted(look_around_result.data.keys()):
        host = look_around_result.data[ts]
        res.observed_labels[ts] = sorted(host.labels)
    return res

@dataclass
class AnalysisResult:
    ioc_ip: str = ""
    ioc_timestamp: str = ""
    days_before: int = 0
    days_after: int = 0

    as_analysis: ASAnalysis = None
    os_analysis: OSAnalysis = None
    ssh_analysis: SSHAnalysis = None
    rdp_analysis: RDPAnalysis = None
    location_analysis: LocationAnalysis = None
    dns_analysis: DNSAnalysis = None
    labels_analysis: LabelsAnalysis = None

def get_analysis_result(look_around_result: censys_utils.LookAroundResult) -> AnalysisResult:
    ioc_host = look_around_result.data.get(look_around_result.ioc_timestamp)
    if ioc_host is None:
        # Since my Censys account can't do historical queries, sometimes ioc_host will be empty.
        # Log an error instead of throwing, and just return empty analysis result (for now)
        # raise ValueError("No data found for the IOC timestamp.")
        return AnalysisResult()

    res = AnalysisResult(ioc_ip=ioc_host.ip, ioc_timestamp=look_around_result.ioc_timestamp, 
                         days_before=look_around_result.days_before,
                         days_after=look_around_result.days_after)
    res.as_analysis = build_as_analysis(look_around_result)
    res.os_analysis = build_os_analysis(look_around_result)
    res.ssh_analysis = build_ssh_analysis(look_around_result)
    res.rdp_analysis = build_rdp_analysis(look_around_result)
    res.location_analysis = build_location_analysis(look_around_result)
    res.dns_analysis = build_dns_analysis(look_around_result)
    res.labels_analysis = build_labels_analysis(look_around_result)
    return res

def analysis_result_to_json(analysis_result: AnalysisResult) -> str:
    return json.dumps(asdict(analysis_result), indent=2)

def analysis_result_from_json(json_str: str) -> AnalysisResult:
    data = json.loads(json_str)

    def load_as_data(d: dict) -> censys_utils.ASData:
        if d is None:
            return None
        return censys_utils.ASData(**d)

    def load_os_data(d: dict) -> censys_utils.OSData:
        if d is None:
            return None
        return censys_utils.OSData(**d)

    def load_ssh_data_list(lst: list) -> List[censys_utils.SSHData]:
        out = []
        for item in lst or []:
            out.append(censys_utils.SSHData(**item))
        return out

    def load_rdp_data_list(lst: list) -> List[censys_utils.RDPData]:
        out = []
        for item in lst or []:
            out.append(censys_utils.RDPData(**item))
        return out

    def load_location_data(d: dict) -> censys_utils.LocationData:
        if d is None:
            return None
        return censys_utils.LocationData(**d)

    def load_dns_data(d: dict) -> censys_utils.DNSData:
        if d is None:
            return None
        return censys_utils.DNSData(**d)

    def load_as_analysis(d: dict) -> ASAnalysis:
        if d is None:
            return None
        ioc_data = load_as_data(d["ioc_data"])
        return ASAnalysis(
            ioc_data=ioc_data,
            observed_asn=d["observed_asn"],
            observed_description=d["observed_description"],
            observed_bgp_prefix=d["observed_bgp_prefix"],
            observed_name=d["observed_name"],
            observed_country_code=d["observed_country_code"],
            observed_updated_at=d["observed_updated_at"],
        )

    def load_os_analysis(d: dict) -> OSAnalysis:
        if d is None:
            return None
        ioc_data = load_os_data(d["ioc_data"])
        return OSAnalysis(
            ioc_data=ioc_data,
            observed_vendor=d["observed_vendor"],
            observed_product=d["observed_product"],
        )

    def load_ssh_analysis(d: dict) -> SSHAnalysis:
        if d is None:
            return None
        ioc_data = load_ssh_data_list(d["ioc_data"])
        return SSHAnalysis(
            ioc_data=ioc_data,
            observed_banners=d["observed_banners"],
            observed_banners_hashes=d["observed_banners_hashes"],
            observed_labels=d["observed_labels"],
            observed_version=d["observed_version"],
            observed_comment=d["observed_comment"],
            observed_host_key_algorithm=d["observed_host_key_algorithm"],
            observed_server_host_key_fingerprint=d["observed_server_host_key_fingerprint"],
        )

    def load_rdp_analysis(d: dict) -> RDPAnalysis:
        if d is None:
            return None
        ioc_data = load_rdp_data_list(d["ioc_data"])
        return RDPAnalysis(
            ioc_data=ioc_data,
            observed_labels=d["observed_labels"],
            observed_certificate=d["observed_certificate"],
        )

    def load_location_analysis(d: dict) -> LocationAnalysis:
        if d is None:
            return None
        ioc_data = load_location_data(d["ioc_data"])
        return LocationAnalysis(
            ioc_data=ioc_data,
            observed_country=d["observed_country"],
            observed_country_code=d["observed_country_code"],
        )

    def load_dns_analysis(d: dict) -> DNSAnalysis:
        if d is None:
            return None
        ioc_data = load_dns_data(d["ioc_data"])
        return DNSAnalysis(
            ioc_data=ioc_data,
            observed_names=d["observed_names"],
        )

    def load_labels_analysis(d: dict) -> LabelsAnalysis:
        if d is None:
            return None
        return LabelsAnalysis(
            ioc_data=d["ioc_data"],
            observed_labels=d["observed_labels"],
        )

    return AnalysisResult(
        ioc_ip=data["ioc_ip"],
        ioc_timestamp=data["ioc_timestamp"],
        days_before=data["days_before"],
        days_after=data["days_after"],
        as_analysis=load_as_analysis(data["as_analysis"]),
        os_analysis=load_os_analysis(data["os_analysis"]),
        ssh_analysis=load_ssh_analysis(data["ssh_analysis"]),
        rdp_analysis=load_rdp_analysis(data["rdp_analysis"]),
        location_analysis=load_location_analysis(data["location_analysis"]),
        dns_analysis=load_dns_analysis(data["dns_analysis"]),
        labels_analysis=load_labels_analysis(data["labels_analysis"]),
    )


