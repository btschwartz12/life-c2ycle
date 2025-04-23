import asyncio
from typing import List
from threatfox import ThreatFoxClient
from dotenv import load_dotenv
import os

import lib.utils as utils

load_dotenv()

THREATFOX_API_KEY = os.getenv("THREATFOX_API_KEY")

if not THREATFOX_API_KEY:
    raise ValueError("Missing Threatfox API credentials.")

async def _get_hosts_async(tag: str, limit: int = 30) -> List[utils.Host]:
    async with ThreatFoxClient(api_key=THREATFOX_API_KEY) as client:
        result = await client.query_tag(tag=tag, limit=limit)

    if not result or "data" not in result:
        raise RuntimeError(f"Threatfox query failed for tag: {tag}")

    ips = []
    timestamps = []
    for entry in result["data"]:
        if entry.get("ioc_type", "") == "ip:port":
            ips.append(entry["ioc"].split(":")[0])
            parts = entry["first_seen"].split(" ")
            date, time = parts[0], parts[1]
            timestamps.append(f"{date}T{time}Z")

    return utils.parse_hosts(ips, timestamps)

def get_hosts(tag: str, limit: int = 30) -> List[utils.Host]:
    return asyncio.run(_get_hosts_async(tag, limit))