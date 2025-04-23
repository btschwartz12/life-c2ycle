This repository contains the code and data for the research project "Tracking the Lifecycle of Malware Command and Control Services", conducted in the Winter 2025 semester of CSE 588.

Authored by Ben Schwartz (@btschwartz12) and Aidan Delwiche (@aidandeli), with special thanks to Aidan Holland and Ariana Mirian from Censys.

Please see the [paper](paper/paper.pdf) for more details on the research and methodology.


## Example Usage

### Step 1: Set up python environment

```bash
$ pwd
/path/to/c2-research-588
$ python3 -m venv env && source env/bin/activate
$ pip install -r requirements.txt
```

Now, create an `.env` file in the root of the repository with the following contents:

```bash
CENSYS_API_ID=<your_censys_api_id>
CENSYS_API_SECRET=<your_censys_api_secret>
THREATFOX_API_KEY=<your_threatfox_api_key>
```

### Step 2: Find C2 IOCs

The script needs a set of `<IP, timestamp>` tuples to perform analysis on. 

You can use the ThreatFox website to find C2s that have been reported in the last 30 days. For example [this](https://threatfox.abuse.ch/browse/malware/win.cobalt_strike/) page on ThreatFox can be used to find [this](https://threatfox.abuse.ch/ioc/1450649/) instance of a Cobalt Strike C2. Make sure to mark down the IPs and timestamps of these.

The script also allows you query the ThreatFox API for specific malware tags. See the following step for more details.

### Step 3. Run the script

#### Providing IOCs manually

You can run the script by manually providing IOCs:
```bash
$ python3 main.py \
    --ips 8.137.100.162,121.33.44.88 \
    --timestamps 2025-03-18T00:01:09Z,2025-03-20T00:04:09Z \
    --malware-name CobaltStrike \
    --days-before 7 \
    --days-after 7
```

#### Providing IOCs from a CSV file

If you want to use a bulk set of IOCs, you can provide a CSV file like this:

```csv
malware,ioc_timestamp,ioc_ip
ermac,2025-02-14T16:01:00Z,103.245.231.9
ermac,2025-02-16T20:01:21Z,45.94.31.85
asyncrat,2025-04-15T00:02:07Z,176.65.142.245
sectoprat,2025-04-05T05:50:39Z,149.248.78.209
```
and then run the script like this:

```bash
$ python3 main.py \
    --csv-file IOCs.csv \
    --days-before 7 \
    --days-after 7
```

#### Using the ThreatFox API

You can also use the ThreatFox API to find IOCs for you:

```bash
$ python3 main.py \
    --threatfox-tag ERMAC,Covenant,Hookbot,AsyncRAT,SectopRAT \
    --days-before 7 \
    --days-after 7
```

### Step 4: View results and generate reports

You can view the parsed scan data in [`paper/results/`](./paper/results/) and the generated diagrams in [`paper/plots/`](./paper/plots/).

Then, to generate the report that you can use to determine a lifetime heuristic, run the following command:

```bash
$ python3 heuristic.py \
    --results-dir paper/results \
    --output-csv data.csv
```

This will print some tables to the console and save the data to a CSV file.
