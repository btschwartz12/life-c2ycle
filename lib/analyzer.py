import os
from rich import print
import lib.analyzer_utils as analyzer_utils
import lib.censys_utils as censys_utils
from typing import List, Dict

import lib.plotting as plotting
import lib.utils as utils

def analyze_individual(c2_type: str, look_around_result: censys_utils.LookAroundResult) -> plotting.HostRanges:
    """Plots individual host analysis."""
    analysis_result: analyzer_utils.AnalysisResult = analyzer_utils.get_analysis_result(look_around_result)
    
    if analysis_result.ioc_ip == "":
        return # no info found
    
    with open(utils.get_analysis_result_filename(c2_type, analysis_result.ioc_ip), "w") as f:
        f.write(analyzer_utils.analysis_result_to_json(analysis_result))

    print(f"[bold green]Now let's ANALYZE {look_around_result.ip}[/bold green]")
    
    host_ranges = plotting.plot_individual_analytics(c2_type, analysis_result)

    return host_ranges

def analyze_aggregate(analytic_results: Dict[str, List[plotting.HostRanges]]) -> None:
    """
    Plots host analysis in the aggregate.
    
    Takes in analytics objects from individual analysis (the top level list is by host)
    Each analytics item has seven categories of information:
        ["AS", "OS", "SSH", "RDP", "Location", "DNS", "Malicious"]
    
    For each of those, there are multiple entries of tuple (label, start_time, width) which we can look at the lifetimes of.

    First we start with "Malicious" to determine the time range of known malicious activity.
        We can get a baseline "c2 observed" amount of time based on this as well
        If any SSH, RDP keys are observed overlapping with this time frame, we can count that in a malware's aggregate "key lifetime" metric
        If any DNS records are observed, we can count in aggregate "DNS lifetime"
    """
    plotting.plot_aggregate_analytics(analytic_results)
