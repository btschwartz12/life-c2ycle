from lib.analyzer_utils import AnalysisResult
import lib.utils as utils
import matplotlib.cm as cm
import matplotlib.pyplot as plt
import matplotlib.colors as mcolors
from rich import print
from collections import defaultdict
from datetime import datetime, timedelta
from typing import List, Dict, Callable, Any, Counter

CATEGORY_LABELS = ["AS", "OS", "SSH", "RDP", "Location", "DNS", "Has C2 Label"]

class DataRange:
    def __init__(self, label: str, start: int, end: int):
        self.label = label
        self.start = start
        self.end = end

class HostRanges:
    def __init__(self, res: AnalysisResult, as_ranges: List[DataRange] = None, os_ranges: List[DataRange] = None, ssh_ranges: List[DataRange] = None,
                 rdp_ranges: List[DataRange] = None, location_ranges: List[DataRange] = None, dns_ranges: List[DataRange] = None, has_c2_ranges: List[DataRange] = None):
        self.res = res
        self.as_ranges = as_ranges
        self.os_ranges = os_ranges
        self.ssh_ranges = ssh_ranges
        self.rdp_ranges = rdp_ranges
        self.location_ranges = location_ranges
        self.dns_ranges = dns_ranges
        self.has_c2_ranges = has_c2_ranges

class AnalysisHandler:
    def __init__(self,
                 get_data: Callable[[Any], Dict[str, Any]], # which dictionary to use from the AnalysisResult
                 normalize: Callable[[Any], Any] = lambda x: x, # any transformations needed for the data
                 is_change: Callable[[Any, Any], bool] = lambda a, b: a != b, # check if data changes 
                 graphable: Callable[[Any], bool] = lambda x: x is not None, # if you can graph the previous data 
                 print_specifier: Callable[[Any], str] = lambda x: str(x)): # any formatting for the graph labels

        self.get_data = get_data
        self.normalize = normalize
        self.is_change = is_change
        self.graphable = graphable
        self.print_specifier = print_specifier

    def analyze(self, analysis_obj) -> List[tuple[str, int, int]]:
        
        data_dict = self.get_data(analysis_obj)
        tuples = []
        beginning_ts = None
        prev_ts = None
        prev_data = None
        last_ts = None


        # i don't like how i wrote these conditionals and logic. but, it works.
        # i will refactor if i have time (this means i won't refactor haha)
        for i, dat in enumerate(data_dict.items()):
            ts, raw_data = dat
            ts_datetime = datetime.fromisoformat(ts.replace('Z', '+00:00'))
            norm_data = self.normalize(raw_data)

            # set start points
            if i == 0:
                beginning_ts = ts_datetime
                prev_data = norm_data
                prev_ts = ts_datetime

            elif norm_data is None or self.is_change(prev_data, norm_data):
                
                if self.graphable(prev_data): # if prev data none, don't graph it. we just hit a transition from none to some data.
                    start = int(prev_ts.timestamp())
                    width = int(ts_datetime.timestamp()) - start
    
                    start = (start - int(beginning_ts.timestamp())) // (60 * 60 * 24)
                    width = width // (60 * 60 * 24)

                    tuples.append((f"{self.print_specifier(prev_data)}", start, width))
                
                prev_data = norm_data
                prev_ts = ts_datetime

            last_ts = ts_datetime

        if prev_data is not None:
            start = int(prev_ts.timestamp())
            width = int(last_ts.timestamp()) - start

            start = (start - int(beginning_ts.timestamp())) // (60 * 60 * 24)
            width = width // (60 * 60 * 24)

            tuples.append((f"{self.print_specifier(prev_data)}", start, width))

        return tuples



def plot_individual_analytics(c2_type: str, res: AnalysisResult) -> HostRanges:
    # host: utils.Host = utils.Host(ip=res.ioc_ip, timestamp=res.ioc_timestamp)
    print(f"[green]Running analytics for {res.ioc_ip}[/green]")
    
    """
    well this was supposed to get some extra AS details censys doesn't return, being the AS category (tell if ISP or hosting)
    but i have to pay for it... sooo that means none of that for the time being
    """
    # as_details = ipinfo_utils.fetch_as_details(res.as_analysis, host)

    # gather the data for plotting. each result is returned as list (bar_label, start, width)
    handlers = [
        AnalysisHandler(lambda d: {ts: (d.observed_asn[ts], d.observed_description[ts]) for ts in d.observed_asn},
                        normalize=lambda x: x if x[0] != 0 and x[1] != "" else None,
                        print_specifier=lambda x: f"{x[0]}: {x[1]}"),
        AnalysisHandler(lambda d: d.observed_product,
                        normalize=lambda x: x.lower() if x else None),
        AnalysisHandler(lambda d: d.observed_server_host_key_fingerprint,
                        normalize=lambda x: x if x else None,
                        print_specifier=lambda x: ", ".join([f"{k}: {v[:5]}..." for k,v in x.items()])), # truncate keys
        AnalysisHandler(lambda d: d.observed_certificate,
                        normalize=lambda x: x if x else None,
                        print_specifier=lambda x: ", ".join([f"{k}: {v[:5]}..." for k,v in x.items()])),
        AnalysisHandler(lambda d: d.observed_country,
                        normalize=lambda x: x if x else None),
        AnalysisHandler(lambda d: d.observed_names,
                        normalize=lambda x: set(x) if x else set([]),
                        is_change=lambda a, b: len(a & b) == 0, #tracking disjoint sets
                        graphable=lambda x: len(x) > 0,
                        print_specifier=lambda x: ", ".join([f"{v[:12]}..." if len(v) > 12 else v for v in x])), # truncate dns names
        AnalysisHandler(lambda d: d.observed_labels,
                        normalize=lambda x: "c2" in set(x) or "bulletproof" in set(x),
                        is_change=lambda a, b: a != b),
    ]

    plot_data = []

    for handler, analysis_obj in zip(handlers, [
        res.as_analysis,
        res.os_analysis,
        res.ssh_analysis,
        res.rdp_analysis,
        res.location_analysis,
        res.dns_analysis,
        res.labels_analysis,
    ]):
        plot_data.append(handler.analyze(analysis_obj))

    host_ranges = HostRanges(res)
    for label, data in zip(CATEGORY_LABELS, plot_data):
        
        ranges = []

        for rng in data:
            ranges.append(DataRange(rng[0], rng[1], rng[2]))
        
        if label == "AS":
            host_ranges.as_ranges = ranges
        elif label == "OS":
            host_ranges.os_ranges = ranges
        elif label == "SSH":
            host_ranges.ssh_ranges = ranges
        elif label == "RDP":
            host_ranges.rdp_ranges = ranges
        elif label == "Location":
            host_ranges.location_ranges = ranges
        elif label == "DNS":
            host_ranges.dns_ranges = ranges
        elif label == "Has C2 Label":
            host_ranges.has_c2_ranges = ranges

    plot_rotations(c2_type, plot_data, res)
    return host_ranges

def plot_rotations(c2_type: str, data: List[List[tuple[str, int, int]]], res: AnalysisResult):
    
    plt.figure(figsize=(14, 6))

    y_positions = {label: i for i, label in enumerate(CATEGORY_LABELS)}
    
    cmap = cm.get_cmap("viridis") # you can pick whatever
    color_cache = defaultdict(dict)
    
    for category_index, segments in enumerate(data):
        category_name = CATEGORY_LABELS[category_index]
        y_pos = y_positions[category_name]
        num_segments = len(segments)

        for i, (label, start, width) in enumerate(segments):
            # Adjust start position relative to baseline (0)
            adjusted_start = start - res.days_before

            if category_name == "Has C2 Label":
                is_c2 = "true" in label.lower()
                color = "green" if is_c2 else "red"
            else:
                # Use cached color if available
                if label in color_cache:
                    color = color_cache[label]
                else:
                    color = cmap(i / max(1, num_segments - 1))  # gradient color
                    color_cache[label] = color
                    

            # draw bar
            plt.barh(
                y=y_pos,
                width=width,
                left=adjusted_start,
                height=0.8,
                color=color,
                edgecolor='black'
            )

            # label in bar
            if width > 0:
                plt.text(
                    adjusted_start + width / 2,
                    y_pos,
                    label,
                    ha='center',
                    va='center',
                    fontsize=8,
                    color= 'white' if mcolors.rgb_to_hsv(mcolors.to_rgb(color))[2] < 0.5
                            else 'black' # make sure you can read the text
                )

    # turn that y axis upsidown yo
    plt.yticks(list(y_positions.values()), CATEGORY_LABELS)
    plt.gca().invert_yaxis()

    # time axis
    ts = datetime.fromisoformat(res.ioc_timestamp.replace('Z', '+00:00'))
    start_date = ts - timedelta(days=res.days_before)
    end_date = ts + timedelta(days=res.days_after)
    
    # Set x-axis limits to center at 0
    plt.xlim(-res.days_before, res.days_after)
    
    # Add vertical line at x=0
    plt.axvline(x=0, color='black', linestyle='--', alpha=0.5)
    
    # Set x-axis ticks to show negative and positive days
    x_ticks = list(range(-res.days_before, res.days_after + 1))
    plt.xticks(x_ticks)
    
    plt.xlabel(f"{start_date.date()} to {end_date.date()} (Days from IOC)")
    plt.title(f'Censys Host Analysis Timeline for {res.ioc_ip}, hosting {c2_type}')
    plt.grid(axis='x', linestyle='--', alpha=0.5)
    plt.tight_layout()
    
    p_fname = utils.get_plot_filename(c2_type, res.ioc_ip)
    plt.savefig(p_fname)
    plt.close()

    print(f"[green]Plot saved to {p_fname}[/green]")


def plot_aggregate_analytics(analytic_results: Dict[str, List[HostRanges]]) -> None:
    """
    Plots host analysis in the aggregate.
    
    Takes in analytics objects from individual analysis (the top level list is by host)
    Each analytics item has seven categories of information:
        ["AS", "OS", "SSH", "RDP", "Location", "DNS", "Has C2 Label"]
    
    For each of those, there are multiple entries of tuple (label, start_time, width) which we can look at the lifetimes of.

    First we start with "Has C2 Label" to determine the time range of known malicious activity.
        We can get a baseline "c2 observed" amount of time based on this as well
        If any SSH, RDP keys are observed overlapping with this time frame, we can count that in a malware's aggregate "key lifetime" metric
        If any DNS records are observed, we can count in aggregate "DNS lifetime"
    """

    print("[bold blue]Running aggregate analytics...[/bold blue]")

    aggregates = {}
    asn_frequencies = {}
    country_frequencies = {}
    global_asn_counter = Counter()
    global_country_counter = Counter()

    for c2_label, hosts in analytic_results.items():
        c2_stats = {}
        for host in hosts:
            if not host:
                continue
            start, end = calc_malicious_range(host.has_c2_ranges)
            ioc_time = host.res.days_before
            stats = {}
            
            # run stats on all labels except OS and Has C2 Label
            track_as_frequencies(host.as_ranges, start, end, ioc_time, c2_label, asn_frequencies, global_asn_counter)
            track_country_frequencies(host.location_ranges, start, end, ioc_time, c2_label, country_frequencies, global_country_counter)
            
            stats["SSH"] = run_stats(host.ssh_ranges, start, end, ioc_time)
            stats["RDP"] = run_stats(host.rdp_ranges, start, end, ioc_time)
            stats["DNS"] = run_stats(host.dns_ranges, start, end, ioc_time)

            update_c2_stats(c2_stats, stats)
        
        aggregates[c2_label] = c2_stats
    
    plot_aggregates(aggregates)
    plot_asn_frequencies(asn_frequencies, global_asn_counter)
    plot_country_frequencies(country_frequencies, global_country_counter)
    print("[bold blue]Finished running aggregate analytics.[/bold blue]")

def update_c2_stats(c2_stats: Dict[str, tuple[float, int]], host_stats: Dict[str, int]) -> None:
    """
    Update running mean statistics for a C2.
    c2_stats[label] = (current_mean, count)
    """

    for label, stat in host_stats.items():
        
        if stat == 0:
            continue
        
        if label not in c2_stats:
            c2_stats[label] = (stat, 1)
        else:
            current_mean, count = c2_stats[label]
            new_count = count + 1
            new_mean = current_mean + (stat - current_mean) / new_count
            c2_stats[label] = (new_mean, new_count)
    
    return

def run_stats(data_points: List[DataRange], start: int, end: int, ioc_time: int) -> float:
    """
    Compute mean lifetime of overlapping entries for a given label.
    """
    count = 0
    mean = 0.0

    for dp in data_points:
        beginning, timespan = dp.start, dp.end
        if beginning <= end and (beginning + timespan) >= start\
            or beginning <= ioc_time and (beginning + timespan) >= ioc_time:
            count += 1
            mean += (timespan - mean) / count

    return mean

def track_as_frequencies(
    data_points: List[DataRange],
    start: int,
    end: int,
    ioc_time: int,
    c2_label: str,
    asn_frequencies: Dict[str, Counter],
    global_asn_counter: Counter,
) -> None:
    """
    Count ASN label frequencies for overlapping intervals.
    """
    for dp in data_points:
        label, beginning, timespan = dp.label, dp.start, dp.end
        if beginning <= end and (beginning + timespan) >= start\
            or beginning <= ioc_time and (beginning + timespan) >= ioc_time:
            asn = label.strip()
            if c2_label not in asn_frequencies:
                asn_frequencies[c2_label] = Counter()
            asn_frequencies[c2_label][asn] += 1
            global_asn_counter[asn] += 1

def track_country_frequencies(
    data_points: List[DataRange],
    start: int,
    end: int,
    ioc_time: int,
    c2_label: str,
    country_frequencies: Dict[str, Counter],
    global_country_counter: Counter,
) -> None:
    """
    Count country frequencies for overlapping intervals.
    """
    for dp in data_points:
        label, beginning, timespan = dp.label, dp.start, dp.end
        if beginning <= end and (beginning + timespan) >= start\
            or beginning <= ioc_time and (beginning + timespan) >= ioc_time:
            country = label.strip()
            if c2_label not in country_frequencies:
                country_frequencies[c2_label] = Counter()
            country_frequencies[c2_label][country] += 1
            global_country_counter[country] += 1

def calc_malicious_range(host: List[DataRange]) -> tuple[int, int]:
    """Find time range that malicious software was run"""

    s, e = 0, 0

    for rng in host:
        label, start, width = rng.label, rng.start, rng.end
        if "true" in label.lower():
            s = start
            e = start + width
    
    return (s, e)

def plot_aggregates(aggregates: Dict[str, Dict[str, tuple[float, int]]]):
    """Create graphs for all aggregate statistics, filling in zeroes where data is missing."""
    label_item = {"SSH": "Key", "RDP": "Certificate", "DNS": "Record"}
    method_full_names = {
        "SSH": "SSH Key",
        "RDP": "RDP Certificate",
        "DNS": "DNS Record"
    }

    method_stats = defaultdict(dict)  # method -> {malware: stat}
    all_malware = set()

    # collect all malware names and organize stats by method
    for malware, stats in aggregates.items():
        all_malware.add(malware)
        for method, (stat, _) in stats.items():
            method_stats[method][malware] = stat

    # for each method, plot stats for all malware (insert 0 if missing)
    for method, malware_to_stat in method_stats.items():
        labels = sorted(all_malware)  # consistent order
        values = [malware_to_stat.get(malware, 0.0) for malware in labels]

        plt.figure(figsize=(8, 4))
        bars = plt.bar(labels, values)

        # color missing values differently
        for i, malware in enumerate(labels):
            if malware not in malware_to_stat:
                bars[i].set_color('gray')  # visually distinguish "missing" data

        plt.title(f"Estimated {method_full_names[method]} Lifetime by Malware Family")
        plt.xlabel("Malware Family")
        plt.ylabel("Observed Lifetime (Days), Upper Bound of IOC Artifact and C2 Label", wrap=True)
        plt.tight_layout()
        p_fname = utils.get_agg_plot_filename(method)
        plt.savefig(p_fname)
        plt.close()
        print(f"[blue]Plot saved to {p_fname}[/blue]")


def plot_asn_frequencies(per_malware_asns: Dict[str, Counter], global_counter: Counter, top_n: int = 10):
    """
    Plot most common ASNs per malware and globally.
    """
    # Per-malware ASN plots
    for malware, counter in per_malware_asns.items():
        most_common = counter.most_common(top_n)
        if not most_common:
            continue
        labels, counts = zip(*most_common)

        plt.figure(figsize=(10, 6))
        plt.barh(labels, counts)
        plt.title(f"Top {top_n} ASNs for {malware}")
        plt.xlabel("Frequency")
        plt.ylabel("ASN")
        plt.gca().invert_yaxis()
        plt.tight_layout()
        fname = utils.get_plot_filename(malware, "ASN")
        plt.savefig(fname)
        plt.close()
        print(f"[blue]ASN plot saved to {fname}[/blue]")


    # Global ASN plot
    top_global = global_counter.most_common(top_n)
    if top_global:
        labels, counts = zip(*top_global)
    
        plt.figure(figsize=(10, 6))
        plt.barh(labels, counts)
        plt.title(f"Top {top_n} ASNs Across All Malware")
        plt.xlabel("Frequency")
        plt.ylabel("ASN")
        plt.gca().invert_yaxis()  # most frequent at the top
        plt.tight_layout()
        plt.savefig(utils.get_agg_plot_filename("ASN"))
        plt.close()
        print(f"[blue]Global ASN plot saved to plots/ASN.png[/blue]")

def plot_country_frequencies(per_malware_countries: Dict[str, Counter], global_counter: Counter, top_n: int = 10):
    """
    Plot most common countries per malware and globally.
    """
    # Per-malware country plots
    for malware, counter in per_malware_countries.items():
        most_common = counter.most_common(top_n)
        if not most_common:
            continue
        labels, counts = zip(*most_common)

        plt.figure(figsize=(10, 6))
        plt.barh(labels, counts)
        plt.title(f"Top {top_n} Countries for {malware}")
        plt.xlabel("Frequency")
        plt.ylabel("Country")
        plt.gca().invert_yaxis()
        plt.tight_layout()
        fname = utils.get_plot_filename(malware, "Country")
        plt.savefig(fname)
        plt.close()
        print(f"[blue]Country plot saved to {fname}[/blue]")

    # Global country plot
    top_global = global_counter.most_common(top_n)
    if top_global:
        labels, counts = zip(*top_global)
    
        plt.figure(figsize=(10, 6))
        plt.barh(labels, counts)
        plt.title(f"Top {top_n} Countries Across All Malware")
        plt.xlabel("Frequency")
        plt.ylabel("Country")
        plt.gca().invert_yaxis()  # most frequent at the top
        plt.tight_layout()
        plt.savefig(utils.get_agg_plot_filename("Country"))
        plt.close()
        print(f"[blue]Global country plot saved to plots/Country.png[/blue]")