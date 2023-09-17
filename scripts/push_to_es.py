from elasticsearch import Elasticsearch
import json
from datetime import datetime
import os
import argparse
from zipfile import ZipFile
import time

parser = argparse.ArgumentParser(
    description="Push Fennec triage image results in JSONL formate to Elasticsearch"
)
parser.add_argument("ES_URL", help="Elasticsearch URL (ex. http://127.0.0.1:9200)")
parser.add_argument("PATH", help="Path to Fennec triage image")
parser.add_argument("-i","--index", help="Elasticsearch index, default is 'fennec'", default="fennec")

args = parser.parse_args()
es = Elasticsearch(args.ES_URL)
startTime = time.time()

print(f"[!] Openning triage image '{args.PATH}'")
with ZipFile(args.PATH, "r") as zip:
    for name in zip.namelist():
        if name.endswith(".jsonl") and not "/" in name:
            with zip.open(name) as ifile:
                print(
                    f"[!] Start processing the file '{name}' and pushing records to ES '{args.ES_URL}'"
                )
                for line in ifile:
                    line = line.decode("utf-8").strip()
                    record = json.loads(line)
                    data = {}
                    data["artifact_name"] = os.path.basename(name).rsplit(".", 1)[0]
                    if record.get("@timestamp"):
                        data["timestamp"] = datetime.strptime(
                            record.pop("@timestamp"), "%Y-%m-%d %H:%M:%S"
                        )
                    else:
                        data["timestamp"] = datetime.strptime(
                            "1970-01-01 00:00:00", "%Y-%m-%d %H:%M:%S"
                        )

                    data.update(record)
                    # print(data)
                    es.index(index=args.index, body=data)
                print(f"[!] Done processing the file '{name}'")

endTime = time.time()
print(f"[!] Done! Took '{endTime - startTime}' seconds")
