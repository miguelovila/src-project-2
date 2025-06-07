import pandas as pd
import numpy as np
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

class CompromisedClientsReport:
    def __init__(self, clients_data):
        self.clients_data = clients_data  # Dict: {ip: {'violations': [...], 'details': {...}}}
    
    def filterBy(self, *filters):
        """Filter clients by violation types or specific IPs"""
        filtered_clients = {}
        
        # Parse filters
        violation_filters = []
        ip_filters = []
        
        for f in filters:
            if isinstance(f, str):
                violation_filters.append(f)
            elif hasattr(f, '__iter__'):  # For client_ip() results
                ip_filters.extend(f)
        
        for client_ip, data in self.clients_data.items():
            # Check IP filters first
            if ip_filters and client_ip not in ip_filters:
                continue
            
            # Check violation filters
            if violation_filters:
                client_violations = ' '.join(data['violations'])
                if all(self._check_violation_filter(vf, client_violations) for vf in violation_filters):
                    filtered_clients[client_ip] = data
            else:
                filtered_clients[client_ip] = data
        
        return CompromisedClientsReport(filtered_clients)
    
    def _check_violation_filter(self, filter_name, violations_text):
        """Check if a violation filter matches"""
        filter_mappings = {
            'protocol_violations': 'protocols',
            'country_violations': 'countries', 
            'asn_violations': 'ASNs',
            'traffic_violations': ['Flow', 'Upload', 'Download'],
            'flow_frequency_violation': 'frequency',
            'internal_ip_violations': 'internal IPs'
        }
        
        if filter_name in filter_mappings:
            keywords = filter_mappings[filter_name]
            if isinstance(keywords, list):
                return any(keyword in violations_text for keyword in keywords)
            else:
                return keywords in violations_text
        return False
    
    def client_ip(self, *ips):
        """Helper function to specify client IPs"""
        return list(ips)
    
    def show(self, detailed=True):
        """Display the filtered results"""
        if not self.clients_data:
            print("No compromised clients found with the specified filters.")
            return
        
        print(f"Filtered Results: {len(self.clients_data)} clients")
        print("=" * 50)
        
        for client_ip, data in self.clients_data.items():
            print(f"\nClient: {client_ip}")
            if detailed and 'details' in data:
                details = data['details']
                print(f"  Flow Change: {details.get('flow_change', 'N/A')}")
                print(f"  Upload Change: {details.get('upload_change', 'N/A')}")
                print(f"  Download Change: {details.get('download_change', 'N/A')}")
                print(f"  Frequency Change: {details.get('frequency_change', 'N/A')}")
            
            print(f"  Violations ({len(data['violations'])}):")
            for violation in data['violations']:
                print(f"    • {violation}")
    
    def summary(self):
        """Show summary statistics"""
        if not self.clients_data:
            print("No clients in current filter.")
            return
        
        total = len(self.clients_data)
        violation_counts = {
            'Protocol': 0, 'Geographic': 0, 'Infrastructure': 0, 
            'Traffic': 0, 'Internal Network': 0
        }
        
        for data in self.clients_data.values():
            violations_text = ' '.join(data['violations'])
            if 'protocols' in violations_text:
                violation_counts['Protocol'] += 1
            if 'countries' in violations_text:
                violation_counts['Geographic'] += 1
            if 'ASNs' in violations_text:
                violation_counts['Infrastructure'] += 1
            if any(t in violations_text for t in ['Flow', 'Upload', 'Download', 'frequency']):
                violation_counts['Traffic'] += 1
            if 'internal IPs' in violations_text:
                violation_counts['Internal Network'] += 1
        
        print(f"Summary for {total} filtered clients:")
        print(f"  Detected Clients IPs: {', '.join(self.clients_data.keys())}")
        for vtype, count in violation_counts.items():
            print(f"  {vtype} violations: {count} clients ({count/total*100:.1f}%)")
    
    def __len__(self):
        return len(self.clients_data)
    
    def __iter__(self):
        return iter(self.clients_data.items())
    
def check_client_behavior_anomalies(normal_data, anomalous_data, client_baseline, server_baseline):
    alerts = 0
    compromised_clients = {}
    info("Running SIEM Rule: Client Behavior Anomaly Detection")
    
    # Pre-compute global sets
    normal_countries = set(normal_data['dst_cc'].unique())
    normal_asns = set(normal_data['dst_asn'].dropna().unique())
    server_ips = list(server_baseline.keys())
    
    # Process client flows in bulk
    client_flows = anomalous_data[~anomalous_data['src_ip'].isin(server_ips)].copy()
    client_flows['minute'] = client_flows['timestamp'] // 6000
    client_flows['proto_port'] = client_flows['proto'] + ':' + client_flows['port'].astype(str)
    client_flows['is_private'] = client_flows['dst_ip'].apply(lambda x: ipaddress.ip_address(x).is_private)
    
    # Aggregate current client data
    current_stats = client_flows.groupby('src_ip').agg({
        'proto_port': lambda x: set(x),
        'dst_cc': lambda x: set([cc for cc in x.dropna() if cc is not None]),
        'dst_asn': lambda x: set([int(asn) for asn in x.dropna()]),
        'dst_ip': lambda x: set(x[client_flows.loc[x.index, 'is_private']]),
        'src_ip': 'count',
        'up_bytes': 'sum',
        'down_bytes': 'sum',
        'minute': 'nunique'
    }).rename(columns={'src_ip': 'flows', 'minute': 'active_minutes'})
    
    # Convert baseline to dict for faster lookup
    baseline_dict = {row['src_ip']: row for _, row in client_baseline.iterrows()}
    
    # Check each client
    for src_ip, stats in current_stats.iterrows():
        if src_ip not in baseline_dict:
            critical(f"Unknown client detected: {src_ip} (not in baseline)")
            alerts += 1
            continue
        
        baseline = baseline_dict[src_ip]
        violations = []
        details = {}
        
        # Protocol violations
        new_protocols = stats['proto_port'] - set(baseline['protocol_ports'])
        if new_protocols:
            violations.append(f"New protocols: {', '.join(new_protocols)}")
        
        # Country violations
        new_countries = stats['dst_cc'] - set(baseline['contacted_countries'])
        if new_countries and not new_countries.issubset(normal_countries):
            violations.append(f"New countries: {', '.join(new_countries)}")
        
        # ASN violations
        new_asns = stats['dst_asn'] - set(baseline['contacted_asns'])
        if new_asns and not new_asns.issubset(normal_asns):
            violations.append(f"New ASNs: {', '.join([f'AS{asn}' for asn in sorted(new_asns)])}")
        
        # Private IP violations
        new_private_ips = stats['dst_ip'] - set(baseline['contacted_private_ip'])
        if new_private_ips:
            violations.append(f"New internal IPs: {', '.join(sorted(new_private_ips))}")
        
        # Traffic anomalies
        flows_per_min = stats['flows'] / stats['active_minutes'] if stats['active_minutes'] > 0 else 0
        changes = {
            'flow_change': ((stats['flows'] - baseline['tot_flows']) / baseline['tot_flows']) * 100,
            'upload_change': ((stats['up_bytes'] - baseline['tot_up_traffic']) / baseline['tot_up_traffic']) * 100 if baseline['tot_up_traffic'] > 0 else 0,
            'download_change': ((stats['down_bytes'] - baseline['tot_down_traffic']) / baseline['tot_down_traffic']) * 100 if baseline['tot_down_traffic'] > 0 else 0,
            'frequency_change': ((flows_per_min - baseline['avg_flows_per_minute']) / baseline['avg_flows_per_minute']) * 100 if baseline['avg_flows_per_minute'] > 0 else 0
        }
        
        details.update(changes)
        
        thresholds = {'flow_change': 100, 'upload_change': 200, 'download_change': 200, 'frequency_change': 100}
        for metric, change in changes.items():
            if abs(change) >= thresholds[metric]:
                if metric == 'flow_change':
                    violations.append(f"Flow count: {change:+.1f}% ({baseline['tot_flows']} -> {stats['flows']})")
                elif 'upload' in metric:
                    violations.append(f"Upload traffic: {change:+.1f}% ({baseline['tot_up_traffic']:,} -> {stats['up_bytes']:,} bytes)")
                elif 'download' in metric:
                    violations.append(f"Download traffic: {change:+.1f}% ({baseline['tot_down_traffic']:,} -> {stats['down_bytes']:,} bytes)")
                elif 'frequency' in metric:
                    violations.append(f"Flow frequency: {change:+.1f}% ({baseline['avg_flows_per_minute']:.2f} -> {flows_per_min:.2f} flows/min)")
        
        if violations:
            compromised_clients[src_ip] = {
                'violations': violations,
                'details': details
            }
            critical(f"Compromised client {src_ip}: {'; '.join(violations)}")
            alerts += 1
    
    # Summary report
    if compromised_clients:
        info(f"Compromised Client Summary: {len(compromised_clients)} total")
    
    info(f"Total alerts: {alerts}" if alerts > 0 else "No client anomalies detected")
    return CompromisedClientsReport(compromised_clients)

def check_external_ddos_attacks(servers_data):
    """
    SIEM Rule: Detect DDoS attacks from external clients based on high flow rates and periodic timing
    """
    alerts = 0
    info("Running SIEM Rule: External DDoS Attack Detection")
    
    # Convert timestamp to seconds for analysis
    analysis_data = servers_data.copy()
    analysis_data['timestamp_sec'] = analysis_data['timestamp'] / 100
    
    # Analyze each external client
    for src_ip in analysis_data['src_ip'].unique():
        client_flows = analysis_data[analysis_data['src_ip'] == src_ip].sort_values('timestamp_sec')
        
        if len(client_flows) < 20:  # Need sufficient flows for analysis
            continue
            
        # Calculate timing metrics
        timestamps = client_flows['timestamp_sec'].values
        inter_arrival_times = np.diff(timestamps)
        
        if len(inter_arrival_times) == 0:
            continue
            
        # Basic metrics
        total_flows = len(client_flows)
        time_span = timestamps.max() - timestamps.min()
        flows_per_second = total_flows / time_span if time_span > 0 else float('inf')
        
        # Timing statistics
        mean_interval = np.mean(inter_arrival_times)
        std_interval = np.std(inter_arrival_times)
        cv = std_interval / mean_interval if mean_interval > 0 else float('inf')
        min_interval = np.min(inter_arrival_times)
        
        # Target analysis
        unique_targets = client_flows['dst_ip'].nunique()
        
        # DDoS Detection Rules
        violations = []
        
        # High flow rate detection
        if flows_per_second >= 10.0:
            violations.append(f"Very high flow rate: {flows_per_second:.2f} flows/sec")
        elif flows_per_second >= 5.0:
            violations.append(f"High flow rate: {flows_per_second:.2f} flows/sec")
                    
        # Artificial timing patterns
        if cv <= 1:
            violations.append(f"Suspicious periodic timing (CV: {cv:.3f})")
        
        # Rapid fire detection (simultaneous requests = bot attack)
        if min_interval <= 0.001:  # Requests at same timestamp or <1ms apart
            violations.append(f"Simultaneous requests (automated attack)")
        elif min_interval < 0.05:
            violations.append(f"Rapid-fire requests (min interval: {min_interval:.3f}s)")
        
        # Volume detection
        if total_flows >= 1000:
            violations.append(f"High volume attack: {total_flows} flows")
        elif total_flows >= 500:
            violations.append(f"Medium volume attack: {total_flows} flows")
        
        # Generate alerts for violators
        if violations:
            violation_summary = "; ".join(violations)
            
            # Determine severity
            if (flows_per_second >= 10.0 or cv <= 0.2 or min_interval <= 0.001 or total_flows >= 1000):
                critical(f"DDoS Attacker {src_ip}: {violation_summary}")
            else:
                warning(f"Suspicious External Client {src_ip}: {violation_summary}")
            
            alerts += 1
    
    # Summary statistics
    total_clients = analysis_data['src_ip'].nunique()
    flagged_clients = alerts
    normal_clients = total_clients - flagged_clients
    
    info(f"External Client Summary:")
    info(f"  Total external clients: {total_clients}")
    info(f"  Flagged as malicious: {flagged_clients}")
    info(f"  Normal clients: {normal_clients}")
    info(f"Total external DDoS alerts: {alerts}" if alerts > 0 else "No external DDoS attacks detected")