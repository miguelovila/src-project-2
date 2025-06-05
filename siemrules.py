import pandas as pd
import ipaddress

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

def check_internal_server_behavior(anomalous_data, server_baseline):
    alerts = 0
    info("Running SIEM Rule: Internal Server Behavior Anomaly Detection")
    
    server_ips = list(server_baseline.keys())
    outbound_servers = anomalous_data[anomalous_data['src_ip'].isin(server_ips)]
    
    if not outbound_servers.empty:
        for server_ip in outbound_servers['src_ip'].unique():
            server_flows = outbound_servers[outbound_servers['src_ip'] == server_ip]
            flow_count = len(server_flows)
            destinations = server_flows['dst_ip'].nunique()
            protocols = (server_flows['proto'] + ':' + server_flows['port'].astype(str)).unique()
            
            critical(f"Server {server_ip} initiating outbound communication: {flow_count} flows to {destinations} destinations using {', '.join(protocols)}")
            alerts += 1
    
    inbound_servers = anomalous_data[anomalous_data['dst_ip'].isin(server_ips)]
    
    if not inbound_servers.empty:
        inbound_servers_with_proto = inbound_servers.copy()
        inbound_servers_with_proto['proto_port'] = inbound_servers_with_proto['proto'] + ':' + inbound_servers_with_proto['port'].astype(str)
        server_protocols = inbound_servers_with_proto.groupby('dst_ip')['proto_port'].apply(lambda x: set(x.unique()))
        server_flow_counts = inbound_servers['dst_ip'].value_counts()
        
        for server_ip, observed_protocols in server_protocols.items():
            if server_ip in server_baseline:
                expected_flows, expected_protocol = server_baseline[server_ip]
                expected_set = {expected_protocol}
                
                new_protocols = observed_protocols - expected_set
                if new_protocols:
                    critical(f"Server {server_ip} receiving traffic on unexpected protocols: {', '.join(new_protocols)} (expected: {expected_protocol})")
                    alerts += 1
                
                current_flows = server_flow_counts.get(server_ip, 0)
                flow_change = ((current_flows - expected_flows) / expected_flows) * 100
                
                if flow_change >= 70:
                    critical(f"Server {server_ip} receiving significantly more traffic: {flow_change:.1f}% increase ({expected_flows} -> {current_flows} flows)")
                    alerts += 1
                elif flow_change >= 35:
                    warning(f"Server {server_ip} receiving moderately more traffic: {flow_change:.1f}% increase ({expected_flows} -> {current_flows} flows)")
                    alerts += 1
                elif flow_change <= -70:
                    critical(f"Server {server_ip} receiving significantly less traffic: {flow_change:.1f}% decrease ({expected_flows} -> {current_flows} flows)")
                    alerts += 1
                elif flow_change <= -35:
                    warning(f"Server {server_ip} receiving moderately less traffic: {flow_change:.1f}% decrease ({expected_flows} -> {current_flows} flows)")
                    alerts += 1
    
    expected_servers = set(server_baseline.keys())
    active_servers = set(anomalous_data[anomalous_data['dst_ip'].isin(server_ips)]['dst_ip'].unique())
    missing_servers = expected_servers - active_servers
    
    for server_ip in missing_servers:
        expected_flows, expected_protocol = server_baseline[server_ip]
        critical(f"Expected server {server_ip} not receiving any traffic (100.0% decrease: {expected_flows} -> 0 flows, expected {expected_protocol})")
        alerts += 1
    
    info(f"Total server behavior alerts generated: {alerts}" if alerts > 0 else "No internal server anomalies detected")

def check_client_behavior_anomalies(normal_data, anomalous_data, client_baseline):
    alerts = 0
    compromised_clients = {}
    info("Running SIEM Rule: Client Behavior Anomaly Detection")
    
    # Convert timestamp to minutes for anomalous data
    anomalous_data_with_minutes = anomalous_data.copy()
    anomalous_data_with_minutes['minute'] = anomalous_data_with_minutes['timestamp'] // 6000
    
    normal_countries = set(normal_data['dst_cc'].unique())
    normal_asns = set(normal_data['dst_asn'].dropna().unique())
    
    # Get client flows (exclude server IPs)
    server_ips = ['192.168.108.234', '192.168.108.240', '192.168.108.233', '192.168.108.231', '192.168.108.237']
    client_flows = anomalous_data_with_minutes[~anomalous_data_with_minutes['src_ip'].isin(server_ips)]
    
    # Process each client in the anomalous data
    for src_ip in client_flows['src_ip'].unique():
        client_data = client_flows[client_flows['src_ip'] == src_ip]
        violations = []
        
        # Find baseline for this client
        baseline_row = client_baseline[client_baseline['src_ip'] == src_ip]
        if baseline_row.empty:
            critical(f"Unknown client detected: {src_ip} (not in baseline)")
            alerts += 1
            continue
            
        baseline = baseline_row.iloc[0]
        
        # Check protocol:port violations
        current_protocols = set((client_data['proto'] + ':' + client_data['port'].astype(str)).unique())
        baseline_protocols = set(baseline['protocol_ports'])
        new_protocols = current_protocols - baseline_protocols
        if new_protocols:
            violations.append(f"New protocols: {', '.join(new_protocols)}")
        
        # Check contacted countries violations
        if 'dst_cc' in client_data.columns:
            current_countries = set([cc for cc in client_data['dst_cc'].unique() if cc is not None])
            baseline_countries = set(baseline['contacted_countries'])
            new_countries = current_countries - baseline_countries
            if new_countries and not new_countries.issubset(normal_countries):
                violations.append(f"New countries: {', '.join(new_countries)}")
        
        # Check contacted ASNs violations
        if 'dst_asn' in client_data.columns:
            current_asns = set([int(asn) for asn in client_data['dst_asn'].dropna().unique()])
            baseline_asns = set(baseline['contacted_asns'])
            new_asns = current_asns - baseline_asns
            if new_asns and not new_asns.issubset(normal_asns):
                violations.append(f"New ASNs: {', '.join([f'AS{asn}' for asn in sorted(new_asns)])}")
        
        # Check private IP violations
        current_private_ips = set(client_data[client_data['dst_ip'].apply(lambda x: ipaddress.ip_address(x).is_private)]['dst_ip'].unique())
        baseline_private_ips = set(baseline['contacted_private_ip'])
        new_private_ips = current_private_ips - baseline_private_ips
        if new_private_ips:
            violations.append(f"New internal IPs: {', '.join(sorted(new_private_ips))}")
        
        # Check traffic volume anomalies
        current_flows = len(client_data)
        baseline_flows = baseline['tot_flows']
        flow_change = ((current_flows - baseline_flows) / baseline_flows) * 100
        
        current_up = client_data['up_bytes'].sum()
        baseline_up = baseline['tot_up_traffic']
        up_change = ((current_up - baseline_up) / baseline_up) * 100 if baseline_up > 0 else 0
        
        current_down = client_data['down_bytes'].sum()
        baseline_down = baseline['tot_down_traffic']
        down_change = ((current_down - baseline_down) / baseline_down) * 100 if baseline_down > 0 else 0
        
        # Check flows per minute
        active_minutes = client_data['minute'].nunique()
        current_flows_per_min = current_flows / active_minutes if active_minutes > 0 else 0
        baseline_flows_per_min = baseline['avg_flows_per_minute']
        flows_per_min_change = ((current_flows_per_min - baseline_flows_per_min) / baseline_flows_per_min) * 100 if baseline_flows_per_min > 0 else 0
        
        # Add traffic anomalies to violations
        if abs(flow_change) >= 100:
            violations.append(f"Flow count: {flow_change:+.1f}% ({baseline_flows} -> {current_flows})")
        if abs(up_change) >= 200:
            violations.append(f"Upload traffic: {up_change:+.1f}% ({baseline_up:,} -> {current_up:,} bytes)")
        if abs(down_change) >= 200:
            violations.append(f"Download traffic: {down_change:+.1f}% ({baseline_down:,} -> {current_down:,} bytes)")
        if abs(flows_per_min_change) >= 100:
            violations.append(f"Flow frequency: {flows_per_min_change:+.1f}% ({baseline_flows_per_min:.2f} -> {current_flows_per_min:.2f} flows/min)")
        
        # Report violations for this client
        if violations:
            compromised_clients[src_ip] = violations
            violation_summary = "; ".join(violations)
            critical(f"Compromised client {src_ip}: {violation_summary}")
            alerts += 1
    
    # Generate summary report
    if compromised_clients:
        info(f"Compromised Client Summary Report:")
        info(f"  Total compromised clients: {len(compromised_clients)}")
        
        # Categorize violations
        protocol_violations = sum(1 for v in compromised_clients.values() if any('protocol' in violation for violation in v))
        country_violations = sum(1 for v in compromised_clients.values() if any('countries' in violation for violation in v))
        asn_violations = sum(1 for v in compromised_clients.values() if any('ASNs' in violation for violation in v))
        traffic_violations = sum(1 for v in compromised_clients.values() if any(any(t in violation for t in ['Flow', 'Upload', 'Download', 'frequency']) for violation in v))
        
        info(f"  Protocol violations: {protocol_violations} clients")
        info(f"  Geographic violations: {country_violations} clients")
        info(f"  Infrastructure violations: {asn_violations} clients")
        info(f"  Traffic anomalies: {traffic_violations} clients")
        
        # List most severely compromised clients (multiple violation types)
        severe_clients = [ip for ip, violations in compromised_clients.items() if len(violations) >= 3]
        if severe_clients:
            info(f"  Severely compromised (≥3 violations): {len(severe_clients)} clients")
            for ip in severe_clients[:5]:  # Show top 5
                info(f"    {ip}: {len(compromised_clients[ip])} violations")
    
    info(f"Total client behavior alerts generated: {alerts}" if alerts > 0 else "No client behavior anomalies detected")
    return compromised_clients