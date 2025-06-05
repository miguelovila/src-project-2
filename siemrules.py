import pandas as pd

def warning(message):
  print(f"\033[1;33m[WARN]\033[0m \033[93m{message}\033[0m")

def low(message):
	print(f"\033[1;32m[LOW]\033[0m \033[92m{message}\033[0m")

def critical(message):
  print(f"\033[1;31m[CRIT]\033[0m \033[91m{message}\033[0m")


def info(message):
  print(f"\033[1;34m[INFO]\033[0m \033[94m{message}\033[0m")


def check_protocol_port_anomalies(normal_counts, anomalous_counts):
  alerts = 0
  info("Running SIEM Rule: Protocol:Port Anomaly Detection")

  new_combinations = set(anomalous_counts.index) - set(normal_counts.index)
  for proto, port in new_combinations:
    critical(f"New protocol:port combination detected: {proto}:{port} ({anomalous_counts[(proto, port)]} flows)")
    alerts += 1

  comparison = normal_counts.to_frame('normal').join(anomalous_counts.to_frame('anomalous'), how='inner')
  changes = ((comparison['anomalous'] - comparison['normal']) / comparison['normal'] * 100)

  for (proto, port), change in changes.items():
    normal_val, anomalous_val = comparison.loc[(proto, port)]
    if change >= 10:
      critical(f"Critical increase in {proto}:{port} traffic: {change:.1f}% increase ({normal_val} -> {anomalous_val} flows)")
      alerts += 1
    elif change >= 5:
      warning(f"Warning increase in {proto}:{port} traffic: {change:.1f}% increase ({normal_val} -> {anomalous_val} flows)")
      alerts += 1
    elif change <= -10:
      warning(f"Significant decrease in {proto}:{port} traffic: {change:.1f}% decrease ({normal_val} -> {anomalous_val} flows)")
      alerts += 1

  missing_combinations = set(normal_counts.index) - set(anomalous_counts.index)
  for proto, port in missing_combinations:
    warning(f"Missing protocol:port combination in anomalous data: {proto}:{port}")
    alerts += 1

  info(f"Total alerts generated: {alerts}" if alerts > 0 else "No protocol:port anomalies detected")


def check_bandwidth_anomalies(normal_data, anomalous_data):
  alerts = 0
  info("Running SIEM Rule: Bandwidth Usage Anomaly Detection")

  normal_bw = normal_data.groupby(["proto", "port"])[["up_bytes", "down_bytes"]].sum()
  anomalous_bw = anomalous_data.groupby(["proto", "port"])[["up_bytes", "down_bytes"]].sum()

  new_combinations = set(anomalous_bw.index) - set(normal_bw.index)
  for proto, port in new_combinations:
    up, down = anomalous_bw.loc[(proto, port)]
    critical(f"New protocol:port combination with bandwidth: {proto}:{port} (Up: {up:,} bytes, Down: {down:,} bytes)")
    alerts += 1

  comparison = normal_bw.join(anomalous_bw, how='inner', lsuffix='_normal', rsuffix='_anomalous')

  for direction in ['up_bytes', 'down_bytes']:
    normal_col = f"{direction}_normal"
    anomalous_col = f"{direction}_anomalous"

    mask = comparison[normal_col] > 0
    changes = ((comparison[anomalous_col] - comparison[normal_col]) / comparison[normal_col] * 100)[mask]

    for (proto, port), change in changes.items():
      normal_val = comparison.loc[(proto, port), normal_col]
      anomalous_val = comparison.loc[(proto, port), anomalous_col]
      traffic_type = "upload" if "up" in direction else "download"

      if change >= 50:
        critical(f"Critical increase in {proto}:{port} {traffic_type} traffic: {change:.1f}% increase ({normal_val:,} -> {anomalous_val:,} bytes)")
        alerts += 1
      elif change >= 20:
        warning(f"Warning increase in {proto}:{port} {traffic_type} traffic: {change:.1f}% increase ({normal_val:,} -> {anomalous_val:,} bytes)")
        alerts += 1
      elif change <= -20:
        warning(f"Significant decrease in {proto}:{port} {traffic_type} traffic: {change:.1f}% decrease ({normal_val:,} -> {anomalous_val:,} bytes)")
        alerts += 1

  missing_combinations = set(normal_bw.index) - set(anomalous_bw.index)
  for proto, port in missing_combinations:
    up, down = normal_bw.loc[(proto, port)]
    warning(f"Missing protocol:port combination in anomalous bandwidth data: {proto}:{port} (Expected Up: {up:,} bytes, Down: {down:,} bytes)")
    alerts += 1

  info(f"Total bandwidth alerts generated: {alerts}" if alerts > 0 else "No bandwidth anomalies detected")

def check_contacted_countries_anomalies(normal_data, anomalous_data):
    alerts = 0
    info("Running SIEM Rule: Contacted Countries Anomaly Detection")

    normal_counts = normal_data['dst_cc'].value_counts()
    anomalous_counts = anomalous_data['dst_cc'].value_counts()

    new_countries = set(anomalous_counts.index) - set(normal_counts.index)
    for country in new_countries:
        critical(f"New country contacted: {country} ({anomalous_counts[country]} flows)")
        alerts += 1

    comparison = normal_counts.to_frame('normal').join(anomalous_counts.to_frame('anomalous'), how='inner')
    changes = ((comparison['anomalous'] - comparison['normal']) / comparison['normal'] * 100)

    for country, change in changes.items():
        normal_val, anomalous_val = comparison.loc[country]
        if change >= 50:
            critical(f"Significant increase in {country} traffic: {change:.1f}% increase ({normal_val} -> {anomalous_val} flows)")
            alerts += 1
        elif change >= 30:
            warning(f"Increase in {country} traffic: {change:.1f}% increase ({normal_val} -> {anomalous_val} flows)")
            alerts += 1
        elif change <= -30:
            warning(f"Significant decrease in {country} traffic: {change:.1f}% decrease ({normal_val} -> {anomalous_val} flows)")
            alerts += 1

    missing_countries = set(normal_counts.index) - set(anomalous_counts.index)
    for country in missing_countries:
        normal_flows = normal_counts[country]
        if normal_flows >= 1000:  # High traffic countries
            critical(f"Missing high-traffic country {country} (100.0% decrease: {normal_flows} -> 0 flows)")
            alerts += 1
        elif normal_flows >= 100:  # Medium traffic countries  
            warning(f"Missing medium-traffic country {country} (100.0% decrease: {normal_flows} -> 0 flows)")
            alerts += 1
        else:  # Low traffic countries
            low(f"Missing low-traffic country {country} (100.0% decrease: {normal_flows} -> 0 flows)")
            alerts += 1

    info(f"Total country alerts generated: {alerts}" if alerts > 0 else "No country anomalies detected")
    
def check_contacted_asns_anomalies(normal_data, anomalous_data):
    alerts = 0
    info("Running SIEM Rule: Contacted ASNs Anomaly Detection")
    asn_org_map = {}
    asn_country_map = {}
    for _, row in normal_data[['dst_asn', 'dst_asn_org', 'dst_cc']].drop_duplicates().iterrows():
        if pd.notna(row['dst_asn']):
            asn_org_map[row['dst_asn']] = row['dst_asn_org']
            asn_country_map[row['dst_asn']] = row['dst_cc']
    for _, row in anomalous_data[['dst_asn', 'dst_asn_org', 'dst_cc']].drop_duplicates().iterrows():
        if pd.notna(row['dst_asn']) and row['dst_asn'] not in asn_org_map:
            asn_org_map[row['dst_asn']] = row['dst_asn_org']
            asn_country_map[row['dst_asn']] = row['dst_cc']
    def format_asn(asn):
        if pd.isna(asn):
            return "UNKNOWN"
        asn_int = int(asn)
        country = asn_country_map.get(asn, "UNKNOWN")
        org = asn_org_map.get(asn, "UNKNOWN")
        return f"({country}) AS{asn_int} {org}"
    normal_countries = set(normal_data['dst_cc'].dropna().unique())
    normal_counts = normal_data['dst_asn'].value_counts()
    anomalous_counts = anomalous_data['dst_asn'].value_counts()
    new_asns = set(anomalous_counts.index) - set(normal_counts.index)
    new_asns_known_countries = 0
    new_asns_unknown_countries = 0
    new_asns_by_country = {}
    for asn in new_asns:
        if pd.notna(asn):
            asn_formatted = format_asn(asn)
            asn_country = asn_country_map.get(asn, "UNKNOWN")
            if asn_country not in new_asns_by_country:
                new_asns_by_country[asn_country] = 0
            new_asns_by_country[asn_country] += 1
            if asn_country in normal_countries:
                warning(f"New ASN from known country: {asn_formatted} ({anomalous_counts[asn]} flows)")
                new_asns_known_countries += 1
                alerts += 1
            else:
                critical(f"New ASN from never contacted country: {asn_formatted} ({anomalous_counts[asn]} flows)")
                new_asns_unknown_countries += 1
                alerts += 1
    comparison = normal_counts.to_frame('normal').join(anomalous_counts.to_frame('anomalous'), how='inner')
    changes = ((comparison['anomalous'] - comparison['normal']) / comparison['normal'] * 100)
    for asn, change in changes.items():
        if pd.notna(asn):
            normal_val, anomalous_val = comparison.loc[asn]
            asn_formatted = format_asn(asn)
            if change >= 50:
                critical(f"Significant increase in {asn_formatted} traffic: {change:.1f}% increase ({normal_val} -> {anomalous_val} flows)")
                alerts += 1
            elif change >= 30:
                warning(f"Increase in {asn_formatted} traffic: {change:.1f}% increase ({normal_val} -> {anomalous_val} flows)")
                alerts += 1
            elif change <= -30:
                warning(f"Significant decrease in {asn_formatted} traffic: {change:.1f}% decrease ({normal_val} -> {anomalous_val} flows)")
                alerts += 1
    missing_asns = set(normal_counts.index) - set(anomalous_counts.index)
    for asn in missing_asns:
        if pd.notna(asn):
            normal_flows = normal_counts[asn]
            asn_formatted = format_asn(asn)
            if normal_flows >= 1000:  # High traffic ASNs
                critical(f"Missing high-traffic ASN {asn_formatted} (100.0% decrease: {normal_flows} -> 0 flows)")
                alerts += 1
            elif normal_flows >= 100:  # Medium traffic ASNs  
                warning(f"Missing medium-traffic ASN {asn_formatted} (100.0% decrease: {normal_flows} -> 0 flows)")
                alerts += 1
            else:  # Low traffic ASNs
                low(f"Missing low-traffic ASN {asn_formatted} (100.0% decrease: {normal_flows} -> 0 flows)")
                alerts += 1
    total_new_asns = new_asns_known_countries + new_asns_unknown_countries
    if total_new_asns > 0:
        known_countries_pct = (new_asns_known_countries / total_new_asns) * 100
        unknown_countries_pct = (new_asns_unknown_countries / total_new_asns) * 100
        info(f"New ASN Statistics:")
        info(f"  Total new ASNs detected: {total_new_asns}")
        info(f"  From known countries: {new_asns_known_countries} ({known_countries_pct:.1f}%)")
        info(f"  From never contacted countries: {new_asns_unknown_countries} ({unknown_countries_pct:.1f}%)")
        sorted_countries = sorted(new_asns_by_country.items(), key=lambda x: x[1], reverse=True)
        info(f"  Breakdown by country:")
        for country, count in sorted_countries:
            country_type = "known" if country in normal_countries else "never contacted"
            info(f"    {country}: {count} ASNs ({country_type})")
        info(f"  Risk assessment: {'HIGH' if unknown_countries_pct > 50 else 'MEDIUM' if unknown_countries_pct > 0 else 'LOW'}")
    info(f"Total ASN alerts generated: {alerts}" if alerts > 0 else "No ASN anomalies detected")
    