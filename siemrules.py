def warning(message):
    print(f"\033[1;33m[WARN]\033[0m \033[93m{message}\033[0m")

def critical(message):
    print(f"\033[1;31m[CRIT]\033[0m \033[91m{message}\033[0m")

def info(message):
    print(f"\033[1;34m[INFO]\033[0m \033[94m{message}\033[0m")

def check_protocol_port_anomalies(normal_counts, anomalous_counts):
    alerts = 0
    
    info("Running SIEM Rule: Protocol:Port Anomaly Detection")
    
    # Check for new protocol:port combinations
    normal_combinations = set(normal_counts.index)
    anomalous_combinations = set(anomalous_counts.index)
    new_combinations = anomalous_combinations - normal_combinations
    
    if new_combinations:
        for proto, port in new_combinations:
            flow_count = anomalous_counts[(proto, port)]
            critical(f"New protocol:port combination detected: {proto}:{port} ({flow_count} flows)")
            alerts += 1
    
    # Check for significant increases in existing combinations
    for (proto, port) in normal_combinations:
        if (proto, port) in anomalous_counts.index:
            normal_count = normal_counts[(proto, port)]
            anomalous_count = anomalous_counts[(proto, port)]
            
            increase_percentage = ((anomalous_count - normal_count) / normal_count) * 100
            
            if increase_percentage >= 10:  # Critical threshold
                critical(f"Critical increase in {proto}:{port} traffic: {increase_percentage:.1f}% increase ({normal_count} -> {anomalous_count} flows)")
                alerts += 1
            elif increase_percentage >= 5:  # Warning threshold
                warning(f"Warning increase in {proto}:{port} traffic: {increase_percentage:.1f}% increase ({normal_count} -> {anomalous_count} flows)")
                alerts += 1
            elif increase_percentage < -10:  # Decrease might also be suspicious
                warning(f"Significant decrease in {proto}:{port} traffic: {increase_percentage:.1f}% decrease ({normal_count} -> {anomalous_count} flows)")
                alerts += 1
    
    missing_combinations = normal_combinations - anomalous_combinations
    if missing_combinations:
        for proto, port in missing_combinations:
            warning(f"Missing protocol:port combination in anomalous data: {proto}:{port}")
            alerts += 1
    
    if alerts == 0:
        info("No protocol:port anomalies detected")
    else:
        info(f"Total alerts generated: {alerts}")