import argparse
from dataclasses import dataclass
import os
import statistics
from rich.table import Table
from rich.console import Console
from rich import print
from typing import Any, Dict, List, Protocol
from lib.analyzer_utils import analysis_result_from_json, AnalysisResult
import math

@dataclass
class LifetimeStats:
    median: float
    mean: float
    min: float
    max: float
    count: int

class LifetimeCalculator(Protocol):
    """Protocol defining the interface for lifetime calculation strategies."""
    def get_timestamps(self, result: AnalysisResult) -> List[Any]:
        """Get the list of timestamps to analyze."""
        ...
    
    def is_valid_for_calculation(self, result: AnalysisResult) -> bool:
        """Check if this result is valid for lifetime calculation."""
        ...
    
    def is_active_at_timestamp(self, result: AnalysisResult, timestamp: Any) -> bool:
        """Check if the C2 is active at the given timestamp."""
        ...

def compute_lifetime_stats(lifetimes: List[int]) -> LifetimeStats:
    if not lifetimes:
        return LifetimeStats(
            median=float('nan'),
            mean=float('nan'),
            min=float('nan'),
            max=float('nan'),
            count=0
        )
    return LifetimeStats(
        median=statistics.median(lifetimes),
        mean=statistics.mean(lifetimes),
        min=min(lifetimes),
        max=max(lifetimes),
        count=len(lifetimes)
    )

def calculate_lifetime(result: AnalysisResult, calculator: LifetimeCalculator) -> int:
    """Calculate the lifetime of a C2 based on the given calculator strategy."""
    if not calculator.is_valid_for_calculation(result):
        return 0
        
    timestamps = calculator.get_timestamps(result)
    ioc_index = timestamps.index(result.ioc_timestamp)
    
    # Count forward
    forward = 0
    for i in range(ioc_index + 1, len(timestamps)):
        if not calculator.is_active_at_timestamp(result, timestamps[i]):
            break
        forward += 1
    
    # Count backward
    backward = 0
    for i in range(ioc_index - 1, -1, -1):
        if not calculator.is_active_at_timestamp(result, timestamps[i]):
            break
        backward += 1
    
    return forward + backward + 1

class C2LabelCalculator(LifetimeCalculator):
    """Calculate lifetime based on C2 labels only."""
    def get_timestamps(self, result: AnalysisResult) -> List[Any]:
        return sorted(result.labels_analysis.observed_labels.keys())
    
    def is_valid_for_calculation(self, result: AnalysisResult) -> bool:
        return "c2" in result.labels_analysis.ioc_data
    
    def is_active_at_timestamp(self, result: AnalysisResult, timestamp: Any) -> bool:
        return "c2" in result.labels_analysis.observed_labels.get(timestamp, [])

class SSHHostKeyCalculator(LifetimeCalculator):
    """Calculate lifetime based on SSH host keys only."""
    def get_timestamps(self, result: AnalysisResult) -> List[Any]:
        return sorted(result.ssh_analysis.observed_server_host_key_fingerprint.keys())
    
    def is_valid_for_calculation(self, result: AnalysisResult) -> bool:
        val = result.ssh_analysis.observed_server_host_key_fingerprint.get(result.ioc_timestamp)
        return val is not None and len(val) > 0
    
    def is_active_at_timestamp(self, result: AnalysisResult, timestamp: Any) -> bool:
        ioc_host_keys = result.ssh_analysis.observed_server_host_key_fingerprint[result.ioc_timestamp]
        observed = result.ssh_analysis.observed_server_host_key_fingerprint.get(timestamp, {})
        return any(
            port in observed and observed[port] == ioc_host_keys.get(port)
            for port in ioc_host_keys
        )

class RDPCertificateCalculator(LifetimeCalculator):
    """Calculate lifetime based on RDP certificates only."""
    def get_timestamps(self, result: AnalysisResult) -> List[Any]:
        return sorted(result.rdp_analysis.observed_certificate.keys())
    
    def is_valid_for_calculation(self, result: AnalysisResult) -> bool:
        val = result.rdp_analysis.observed_certificate.get(result.ioc_timestamp)
        return val is not None and len(val) > 0
    
    def is_active_at_timestamp(self, result: AnalysisResult, timestamp: Any) -> bool:
        ioc_certificate = result.rdp_analysis.observed_certificate[result.ioc_timestamp]
        observed = result.rdp_analysis.observed_certificate.get(timestamp)
        return observed == ioc_certificate

class C2LabelOrSSHHostKeyCalculator(LifetimeCalculator):
    """Calculate lifetime based on either C2 labels or SSH host keys."""
    def __init__(self):
        self.c2_calc = C2LabelCalculator()
        self.ssh_calc = SSHHostKeyCalculator()
    
    def get_timestamps(self, result: AnalysisResult) -> List[Any]:
        # Use SSH timestamps as they're more granular
        return self.ssh_calc.get_timestamps(result)
    
    def is_valid_for_calculation(self, result: AnalysisResult) -> bool:
        return (self.c2_calc.is_valid_for_calculation(result) and 
                self.ssh_calc.is_valid_for_calculation(result))
    
    def is_active_at_timestamp(self, result: AnalysisResult, timestamp: Any) -> bool:
        return (self.c2_calc.is_active_at_timestamp(result, timestamp) or
                self.ssh_calc.is_active_at_timestamp(result, timestamp))

class C2LabelAndSSHHostKeyCalculator(LifetimeCalculator):
    """Calculate lifetime based on both C2 labels AND SSH host keys."""
    def __init__(self):
        self.c2_calc = C2LabelCalculator()
        self.ssh_calc = SSHHostKeyCalculator()
    
    def get_timestamps(self, result: AnalysisResult) -> List[Any]:
        # Use SSH timestamps as they're more granular
        return self.ssh_calc.get_timestamps(result)
    
    def is_valid_for_calculation(self, result: AnalysisResult) -> bool:
        return (self.c2_calc.is_valid_for_calculation(result) and 
                self.ssh_calc.is_valid_for_calculation(result))
    
    def is_active_at_timestamp(self, result: AnalysisResult, timestamp: Any) -> bool:
        return (self.c2_calc.is_active_at_timestamp(result, timestamp) and
                self.ssh_calc.is_active_at_timestamp(result, timestamp))

class C2LabelAndRDPCertificateCalculator(LifetimeCalculator):
    """Calculate lifetime based on both C2 labels AND RDP certificates."""
    def __init__(self):
        self.c2_calc = C2LabelCalculator()
        self.rdp_calc = RDPCertificateCalculator()
    
    def get_timestamps(self, result: AnalysisResult) -> List[Any]:
        # Get all timestamps from both sources and sort them
        c2_timestamps = set(self.c2_calc.get_timestamps(result))
        rdp_timestamps = set(self.rdp_calc.get_timestamps(result))
        return sorted(c2_timestamps | rdp_timestamps)
    
    def is_valid_for_calculation(self, result: AnalysisResult) -> bool:
        return (self.c2_calc.is_valid_for_calculation(result) and 
                self.rdp_calc.is_valid_for_calculation(result))
    
    def is_active_at_timestamp(self, result: AnalysisResult, timestamp: Any) -> bool:
        return (self.c2_calc.is_active_at_timestamp(result, timestamp) and
                self.rdp_calc.is_active_at_timestamp(result, timestamp))

class C2LabelAndDNSRecordCalculator(LifetimeCalculator):
    """Calculate lifetime based on both C2 labels AND DNS records."""
    def __init__(self):
        self.c2_calc = C2LabelCalculator()
    
    def get_timestamps(self, result: AnalysisResult) -> List[Any]:
        return sorted(result.dns_analysis.observed_names.keys())
    
    def is_valid_for_calculation(self, result: AnalysisResult) -> bool:
        return (self.c2_calc.is_valid_for_calculation(result) and 
                result.dns_analysis.observed_names.get(result.ioc_timestamp) is not None)
    
    def is_active_at_timestamp(self, result: AnalysisResult, timestamp: Any) -> bool:
        ioc_names = set(result.dns_analysis.observed_names[result.ioc_timestamp])
        observed = set(result.dns_analysis.observed_names.get(timestamp, []))
        return (self.c2_calc.is_active_at_timestamp(result, timestamp) and
                len(ioc_names & observed) > 0)  # Check if there's any overlap in DNS names

class C2LabelAndSSHHostKeyAndRDPCertificateCalculator(LifetimeCalculator):
    """Calculate lifetime based on C2 labels AND SSH host keys AND RDP certificates."""
    def __init__(self):
        self.c2_calc = C2LabelCalculator()
        self.ssh_calc = SSHHostKeyCalculator()
        self.rdp_calc = RDPCertificateCalculator()
    
    def get_timestamps(self, result: AnalysisResult) -> List[Any]:
        # Use SSH timestamps as they're more granular
        return self.ssh_calc.get_timestamps(result)
    
    def is_valid_for_calculation(self, result: AnalysisResult) -> bool:
        return (self.c2_calc.is_valid_for_calculation(result) and 
                self.ssh_calc.is_valid_for_calculation(result) and
                self.rdp_calc.is_valid_for_calculation(result))
    
    def is_active_at_timestamp(self, result: AnalysisResult, timestamp: Any) -> bool:
        return (self.c2_calc.is_active_at_timestamp(result, timestamp) and
                self.ssh_calc.is_active_at_timestamp(result, timestamp) and
                self.rdp_calc.is_active_at_timestamp(result, timestamp))

class C2LabelAndOSTypeCalculator(LifetimeCalculator):
    """Calculate lifetime based on both C2 labels AND OS type."""
    def __init__(self):
        self.c2_calc = C2LabelCalculator()
    
    def get_timestamps(self, result: AnalysisResult) -> List[Any]:
        return sorted(result.os_analysis.observed_product.keys())
    
    def is_valid_for_calculation(self, result: AnalysisResult) -> bool:
        return (self.c2_calc.is_valid_for_calculation(result) and 
                result.os_analysis.observed_product.get(result.ioc_timestamp) is not None)
    
    def is_active_at_timestamp(self, result: AnalysisResult, timestamp: Any) -> bool:
        ioc_os = result.os_analysis.observed_product[result.ioc_timestamp]
        observed = result.os_analysis.observed_product.get(timestamp)
        return (self.c2_calc.is_active_at_timestamp(result, timestamp) and
                observed == ioc_os)

class DNSRecordCalculator(LifetimeCalculator):
    """Calculate lifetime based on DNS records only."""
    def get_timestamps(self, result: AnalysisResult) -> List[Any]:
        return sorted(result.dns_analysis.observed_names.keys())
    
    def is_valid_for_calculation(self, result: AnalysisResult) -> bool:
        return result.dns_analysis.observed_names.get(result.ioc_timestamp) is not None
    
    def is_active_at_timestamp(self, result: AnalysisResult, timestamp: Any) -> bool:
        ioc_names = set(result.dns_analysis.observed_names[result.ioc_timestamp])
        observed = set(result.dns_analysis.observed_names.get(timestamp, []))
        return len(ioc_names & observed) > 0  # Check if there's any overlap in DNS names

class C2LabelOrRDPCertificateCalculator(LifetimeCalculator):
    """Calculate lifetime based on EITHER C2 labels OR RDP certificates."""
    def __init__(self):
        self.c2_calc = C2LabelCalculator()
        self.rdp_calc = RDPCertificateCalculator()
    
    def get_timestamps(self, result: AnalysisResult) -> List[Any]:
        # Get all timestamps from both sources and sort them
        c2_timestamps = set(self.c2_calc.get_timestamps(result))
        rdp_timestamps = set(self.rdp_calc.get_timestamps(result))
        return sorted(c2_timestamps | rdp_timestamps)
    
    def is_valid_for_calculation(self, result: AnalysisResult) -> bool:
        return (self.c2_calc.is_valid_for_calculation(result) or 
                self.rdp_calc.is_valid_for_calculation(result))
    
    def is_active_at_timestamp(self, result: AnalysisResult, timestamp: Any) -> bool:
        return (self.c2_calc.is_active_at_timestamp(result, timestamp) or
                self.rdp_calc.is_active_at_timestamp(result, timestamp))

class C2LabelOrDNSRecordCalculator(LifetimeCalculator):
    """Calculate lifetime based on EITHER C2 labels OR DNS records."""
    def __init__(self):
        self.c2_calc = C2LabelCalculator()
        self.dns_calc = DNSRecordCalculator()
    
    def get_timestamps(self, result: AnalysisResult) -> List[Any]:
        # Use DNS timestamps as they're more granular
        return self.dns_calc.get_timestamps(result)
    
    def is_valid_for_calculation(self, result: AnalysisResult) -> bool:
        return (self.c2_calc.is_valid_for_calculation(result) or 
                self.dns_calc.is_valid_for_calculation(result))
    
    def is_active_at_timestamp(self, result: AnalysisResult, timestamp: Any) -> bool:
        return (self.c2_calc.is_active_at_timestamp(result, timestamp) or
                self.dns_calc.is_active_at_timestamp(result, timestamp))

class OSTypeCalculator(LifetimeCalculator):
    """Calculate lifetime based on OS type only."""
    def get_timestamps(self, result: AnalysisResult) -> List[Any]:
        return sorted(result.os_analysis.observed_product.keys())
    
    def is_valid_for_calculation(self, result: AnalysisResult) -> bool:
        return result.os_analysis.observed_product.get(result.ioc_timestamp) is not None
    
    def is_active_at_timestamp(self, result: AnalysisResult, timestamp: Any) -> bool:
        ioc_os = result.os_analysis.observed_product[result.ioc_timestamp]
        observed = result.os_analysis.observed_product.get(timestamp)
        return observed == ioc_os

def compute_lifetime_stats_with_calculator(
    analysis_results: List[AnalysisResult],
    calculator: LifetimeCalculator
) -> LifetimeStats:
    lifetimes = []
    for res in analysis_results:
        lifetime = calculate_lifetime(res, calculator)
        if lifetime > 0:
            lifetimes.append(lifetime)
    return compute_lifetime_stats(lifetimes)

def generate_lifetime_table(analysis_results: List[AnalysisResult]) -> Table:
    calculators = {
        "C2 Label Only": C2LabelCalculator(),
        "SSH Host Key Only": SSHHostKeyCalculator(),
        "RDP Certificate Only": RDPCertificateCalculator(),
        "DNS Record Only": DNSRecordCalculator(),
        "OS Type Only": OSTypeCalculator(),
        "C2 Label OR SSH Host Key": C2LabelOrSSHHostKeyCalculator(),
        "C2 Label OR RDP Certificate": C2LabelOrRDPCertificateCalculator(),
        "C2 Label OR DNS Record": C2LabelOrDNSRecordCalculator(),
        "C2 Label AND SSH Host Key": C2LabelAndSSHHostKeyCalculator(),
        "C2 Label AND RDP Certificate": C2LabelAndRDPCertificateCalculator(),
        "C2 Label AND DNS Record": C2LabelAndDNSRecordCalculator(),
        "C2 Label AND OS Type": C2LabelAndOSTypeCalculator(),
    }

    table = Table(title="Estimated C2 Lifetimes by Observed Metrics")
    table.add_column("Metric Combination", style="bold")
    table.add_column("Median Lifetime (days)")
    table.add_column("Mean Lifetime (days)")
    table.add_column("Min (days)")
    table.add_column("Max (days)")
    table.add_column("Instances (N)")
    
    for name, calculator in calculators.items():
        stats = compute_lifetime_stats_with_calculator(analysis_results, calculator)
        table.add_row(
            name,
            f"{stats.median:.2f}" if not math.isnan(stats.median) else "N/A",
            f"{stats.mean:.2f}" if not math.isnan(stats.mean) else "N/A",
            f"{stats.min:.2f}" if not math.isnan(stats.min) else "N/A",
            f"{stats.max:.2f}" if not math.isnan(stats.max) else "N/A",
            f"{stats.count}"
        )
    return table

def write_lifetime_csv(analysis_results_by_family: Dict[str, List[AnalysisResult]], output_file: str):
    """Write lifetime statistics to a CSV file in a format suitable for LaTeX import."""
    import csv
    
    calculators = {
        "C2 Label": C2LabelCalculator(),
        "SSH Host Key": SSHHostKeyCalculator(),
        "RDP Certificate": RDPCertificateCalculator(),
        "DNS Record": DNSRecordCalculator(),
        "OS Type": OSTypeCalculator(),
        "C2 Label or SSH Host Key": C2LabelOrSSHHostKeyCalculator(),
        "C2 Label or RDP Certificate": C2LabelOrRDPCertificateCalculator(),
        "C2 Label or DNS Record": C2LabelOrDNSRecordCalculator(),
        "C2 Label and SSH Host Key": C2LabelAndSSHHostKeyCalculator(),
        "C2 Label and RDP Certificate": C2LabelAndRDPCertificateCalculator(),
        "C2 Label and DNS Record": C2LabelAndDNSRecordCalculator(),
        "C2 Label and OS Type": C2LabelAndOSTypeCalculator(),
    }
    
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        
        # Write header
        writer.writerow(['Metric Combination', 'Family', 'Median', 'Mean', 'Min', 'Max', 'Instances'])
        
        # Write data for each family
        for family_name, family_results in analysis_results_by_family.items():
            for name, calculator in calculators.items():
                stats = compute_lifetime_stats_with_calculator(family_results, calculator)
                writer.writerow([
                    name,
                    family_name,
                    f"{stats.median:.2f}" if not math.isnan(stats.median) else "N/A",
                    f"{stats.mean:.2f}" if not math.isnan(stats.mean) else "N/A",
                    f"{stats.min:.2f}" if not math.isnan(stats.min) else "N/A",
                    f"{stats.max:.2f}" if not math.isnan(stats.max) else "N/A",
                    stats.count
                ])
        
        # Write aggregate data
        combined_results = []
        for results in analysis_results_by_family.values():
            combined_results.extend(results)
        
        for name, calculator in calculators.items():
            stats = compute_lifetime_stats_with_calculator(combined_results, calculator)
            writer.writerow([
                name,
                'Aggregate',
                f"{stats.median:.2f}" if not math.isnan(stats.median) else "N/A",
                f"{stats.mean:.2f}" if not math.isnan(stats.mean) else "N/A",
                f"{stats.min:.2f}" if not math.isnan(stats.min) else "N/A",
                f"{stats.max:.2f}" if not math.isnan(stats.max) else "N/A",
                stats.count
            ])

def main():
    parser = argparse.ArgumentParser(
        description="Compute lifetime heuristics for C2 malware families."
    )
    parser.add_argument(
        "--family", required=False, type=str, 
        help="C2 malware family to compute heuristics for."
    )
    parser.add_argument(
        "--results-dir", required=False, type=str, 
        help="Directory containing analysis results to compute heuristics for.",
        default="paper/results"
    )
    parser.add_argument(
        "--output-csv", required=False, type=str,
        help="Output CSV file for LaTeX import. If not specified, only prints to console.",
        default=None
    )
    args = parser.parse_args()
    results_dir = args.results_dir

    analysis_results_by_family: Dict[str, List[AnalysisResult]] = {}
    for file in os.listdir(results_dir):
        if file.endswith(".json"):
            family_name, _, _ = file.split("_", 2)
            if family_name not in analysis_results_by_family:
                analysis_results_by_family[family_name] = []
            with open(os.path.join(results_dir, file), "r") as f:
                analysis_result = analysis_result_from_json(f.read())
                analysis_results_by_family[family_name].append(analysis_result)
    
    print(f"[bold green]Found {len(analysis_results_by_family)} families[/bold green]")
    
    console = Console()
    
    for family_name, family_results in analysis_results_by_family.items():
        print(f"\n[bold blue]Lifetime Statistics for {family_name}[/bold blue]")
        table = generate_lifetime_table(family_results)
        console.print(table)
    
    if len(analysis_results_by_family) > 1:
        print("\n[bold yellow]Aggregate Lifetime Statistics (All Families)[/bold yellow]")
        combined_results = []
        for results in analysis_results_by_family.values():
            combined_results.extend(results)
        table = generate_lifetime_table(combined_results)
        console.print(table)
    
    # Write CSV if requested
    if args.output_csv:
        write_lifetime_csv(analysis_results_by_family, args.output_csv)
        print(f"\n[bold green]CSV data written to {args.output_csv}[/bold green]")

if __name__ == "__main__":
    main()
