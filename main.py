import argparse
from typing import List, Dict
from rich import print
import lib.analyzer as analyzer
import lib.censys_utils as censys_utils
import lib.threatfox_utils as threatfox_utils
import lib.utils as utils
import csv
from collections import defaultdict


def research_hosts(hosts: Dict[str, List[utils.Host]], days_before: int, days_after: int):
    """
    Analyzes the given IP address at a specific timestamp to identify services 
    running on ports labeled with C2 activity. Once identified, it explores the 
    specified time range before and after the given timestamp to check if these 
    services persist over time.
    """

    results: Dict[str, List[censys_utils.LookAroundResult]] = {}
    
    for c2_type, group in hosts.items():
        
        results[c2_type] = []            
            
        for host in group:
            print(f"[yellow]Looking around {host.ip} [red]{days_before}[/red] days before and [red]{days_after}[/red] days after {host.timestamp}...[/yellow]")
            results[c2_type].append(censys_utils.look_around(host, days_before, days_after))
    
    analytics = {}
    for c2_type, group in results.items():
        
        analytics[c2_type] = []
        
        for result in group:
            analytics[c2_type].append(analyzer.analyze_individual(c2_type, result))

    if len(analytics.keys()) > 0:
        analyzer.analyze_aggregate(analytics)

parser = argparse.ArgumentParser(description="Retrieve Censys host information using an IP and RFC3339 timestamp.")
parser.add_argument("--csv-file", required=False, type=str, help="CSV file containing Malware tags, IPs and timestamps.")
parser.add_argument("--threatfox-tag", required=False, type=str, help="Threatfox tag to lookup IPs (i.e. not using --ips or --timestamps).")
parser.add_argument("--malware-name", required=False, type=str, help="Malware name associated with IPs and timestamps given.")
parser.add_argument("--ips", required=False, type=str, help="Comma-separated list of IP addresses to look up.")
parser.add_argument("--timestamps", required=False, type=str, help="Comma-separated list of RFC3339 timestamps (e.g. 2021-03-01T17:49:05Z). Must correspond to the IPs provided.")
parser.add_argument("--days-before", required=True, type=int, help="Number of days before the C2 instance to look up.")
parser.add_argument("--days-after", required=True, type=int, help="Number of days after the C2 instance to look up.")

def main():
    args = parser.parse_args()

    if (args.threatfox_tag is not None) == (args.ips is not None and args.timestamps is not None and args.malware_name is not None) and args.csv_file is None:
        raise ValueError("You must provide either --csv-file OR --threatfox-tag OR --ips, --timestamps, and --malware-name, but not all.")

    if args.threatfox_tag:
        hosts = {}
        tags = args.threatfox_tag.split(",")
        for tag in tags:
            hosts[tag] = threatfox_utils.get_hosts(tag=tag)
    
    elif args.csv_file:
        hosts = defaultdict(list)
        
        with open(args.csv_file, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                malware = row["malware"]
                ip = row["ioc_ip"]
                timestamp = row["ioc_timestamp"]
                hosts[malware].append(utils.Host(ip, timestamp))

    else:
        hosts = {f"{args.malware_name}": utils.parse_hosts(args.ips.split(","), args.timestamps.split(","))}

    research_hosts(hosts, args.days_before, args.days_after)

if __name__ == "__main__":
    main()
