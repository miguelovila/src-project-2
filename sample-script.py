import os
import ipaddress
import numpy as np
import pandas as pd
import dns.resolver
import geoip2.database
import dns.reversename
import matplotlib.pyplot as plt

script_directory = os.path.dirname(os.path.abspath(__file__))

# Define the dataset to be used
datafile = os.path.join(script_directory, "datasets/test8.parquet")

# IP geolocalization databases
geoASN = geoip2.database.Reader(
    os.path.join(script_directory, "databases/geolite2-asn.mmdb")
)
geoCC = geoip2.database.Reader(
    os.path.join(script_directory, "databases/geolite2-country.mmdb")
)

addr = "193.136.73.21"
cc = geoCC.country("193.136.176.1").country.iso_code
org = geoASN.asn("193.136.176.1").autonomous_system_organization
print("[INFO] CC and ORG: ", cc, org)

### DNS resolution
addr = dns.resolver.resolve("www.ua.pt", "A")
for a in addr:
    print(a)

### Reverse DNS resolution
name = dns.reversename.from_address("193.136.172.20")
addr = dns.resolver.resolve(name, "PTR")
for a in addr:
    print(a)

### Read parquet data files
data = pd.read_parquet(datafile)
print(data)
# print(data.to_string())

# Just the UDP flows
udpF = data.loc[data["proto"] == "udp"]

# Number of UDP flows for each source IP
nudpF = data.loc[data["proto"] == "udp"].groupby(["src_ip"])["up_bytes"].count()

# Number of UDP flows to port 443, for each source IP
nudpF443 = (
    data.loc[(data["proto"] == "udp") & (data["port"] == 443)]
    .groupby(["src_ip"])["up_bytes"]
    .count()
)

# Average number of downloaded bytes, per flow, for each source IP
avgUp = data.groupby(["src_ip"])["down_bytes"].mean()
print(avgUp)

# Total uploaded bytes to destination port 443, for each destination IP, ordered from larger amount to lowest amount
upS = (
    data.loc[((data["port"] == 443))]
    .groupby(["dst_ip"])["up_bytes"]
    .sum()
    .sort_values(ascending=False)
)
print(upS.head(10))

# Upload/Download bytes ratio (traffic for port 443) for each source IP
a1 = data.loc[((data["port"] == 443))].groupby(["src_ip"])["up_bytes"].sum()
a2 = data.loc[((data["port"] == 443))].groupby(["src_ip"])["down_bytes"].sum()
a3 = pd.DataFrame(a2 / a1, columns=["ratio"])
a4 = pd.concat([a1, a2, a3], axis=1).sort_values(by="ratio")
avgRatio = (a2 / a1).mean()
stdRatio = (a2 / a1).std()
print(a4.sort_values(by="ratio").head(10))
print(a4.sort_values(by="ratio", ascending=False).head(10))
print(avgRatio, stdRatio)

# Is destination IPv4 a public address?
NET = ipaddress.IPv4Network("192.168.0.0/16")
bpublic = data.apply(lambda x: ipaddress.IPv4Address(x["dst_ip"]) not in NET, axis=1)
# Add column to DataFrame
bpublicDF = bpublic.to_frame(name="dst_public")
newdata = pd.concat([data, bpublicDF], axis=1)
print(newdata)

# Average interval between flows from same source IP (for each source IP)
data["diff_timestamp"] = data.groupby(["src_ip"])["timestamp"].diff().fillna(0)
interFlowT = (
    data.groupby(["src_ip"])["diff_timestamp"].mean().sort_values(ascending=False)
)
print(interFlowT)
