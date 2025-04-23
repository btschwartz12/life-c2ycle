import csv
from collections import defaultdict
import sys

# Define the desired order of metric combinations
METRIC_ORDER = [
    "C2 Label",
    "SSH Host Key",
    "RDP Certificate",
    "DNS Record",
    "OS Type",
    "C2 Label or SSH Host Key",
    "C2 Label or RDP Certificate",
    "C2 Label or DNS Record",
    "C2 Label and SSH Host Key",
    "C2 Label and RDP Certificate",
    "C2 Label and DNS Record",
    "C2 Label and OS Type"
]

# Mapping for correct family name capitalization
FAMILY_CAPITALIZATION = {
    'covenant': 'Covenant',
    'sectoprat': 'SectopRAT',
    'asyncrat': 'AsyncRAT',
    'hookbot': 'HookBot',
    'ermac': 'ERMAC'
}

if len(sys.argv) != 3:
    print("Usage: python transform_data.py <input_file> <output_file>")
    sys.exit(1)

input_file = sys.argv[1]
output_file = sys.argv[2]

# Read the CSV file and organize data
data = defaultdict(dict)
aggregate_data = {}
families = set()
metric_combinations = set()
instance_counts = {}

with open(input_file, 'r') as f:
    reader = csv.DictReader(f)
    for row in reader:
        family = row['Family']
        # Capitalize the family name correctly
        family = FAMILY_CAPITALIZATION.get(family.lower(), family)
        metric = row['Metric Combination']
        mean = row['Mean']
        median = row['Median']
        instances = row['Instances']
        
        if family == 'Aggregate':
            aggregate_data[metric] = f"{median}/{mean} ({instances})" if mean != 'N/A' else "N/A"
            continue
            
        families.add(family)
        metric_combinations.add(metric)
        data[metric][family] = f"{median}/{mean} ({instances})" if mean != 'N/A' else "N/A"

# Write the transformed data
with open(output_file, 'w', newline='') as f:
    writer = csv.writer(f)
    
    # Write header
    header = ['Metric Combination'] + sorted(families) + ['Aggregate']
    writer.writerow(header)
    
    # Write data rows in the specified order
    for metric in METRIC_ORDER:
        if metric in metric_combinations:  # Only write if the metric exists in the data
            row = [metric]
            for family in sorted(families):
                row.append(data[metric].get(family, "N/A"))
            row.append(aggregate_data.get(metric, "N/A"))
            writer.writerow(row) 