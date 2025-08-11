import subprocess
import json
from collections import defaultdict
import argparse

# ------------------------------
# Helper functions for resource parsing
# ------------------------------
def parse_cpu(cpu_value):
    """Parse CPU value (handles 'm' suffix for millicores)"""
    if not cpu_value:
        return 0.0
    cpu_str = str(cpu_value).strip().lower()
    try:
        if cpu_str.endswith('m'):
            return float(cpu_str[:-1]) / 1000.0
        else:
            return float(cpu_str)
    except (ValueError, TypeError):
        return 0.0

def parse_memory(mem_value):
    """Parse memory value (handles common Kubernetes units)"""
    if not mem_value:
        return 0
    mem_str = str(mem_value).strip().lower()
    memory_units = {
        'k': 1000, 'm': 1000**2, 'g': 1000**3, 't': 1000**4,
        'p': 1000**5, 'e': 1000**6,
        'ki': 1024, 'mi': 1024**2, 'gi': 1024**3, 'ti': 1024**4,
        'pi': 1024**5, 'ei': 1024**6,
    }

    unit = ''
    if len(mem_str) >= 2 and mem_str[-2:] in memory_units:
        unit = mem_str[-2:]
        num_str = mem_str[:-2]
    elif len(mem_str) >= 1 and mem_str[-1] in memory_units:
        unit = mem_str[-1]
        num_str = mem_str[:-1]
    else:
        num_str = mem_str

    try:
        num = float(num_str)
        return num * memory_units.get(unit, 1)
    except (ValueError, TypeError):
        return 0

def parse_pods(pod_value):
    """Parse pod count value"""
    if not pod_value:
        return 0
    try:
        return int(pod_value)
    except (ValueError, TypeError):
        return 0

def format_memory(bytes_value):
    """Convert bytes to human-readable format"""
    if bytes_value == 0:
        return "0"
    units = [
        ('Ei', 1024**6), ('Pi', 1024**5), ('Ti', 1024**4),
        ('Gi', 1024**3), ('Mi', 1024**2), ('Ki', 1024), ('B', 1)
    ]
    for unit, factor in units:
        if bytes_value >= factor:
            return f"{bytes_value/factor:.2f} {unit}"
    return f"{bytes_value} B"

def calculate_percentage(used, total):
    """Calculate percentage with error handling for division by zero"""
    if total <= 0:
        return "N/A"
    return f"{(used / total) * 100:.2f}%"

# ------------------------------
# Resource configuration check functions
# ------------------------------
def has_missing_resources(pod):
    """Check if a pod is missing any resource requests or limits"""
    return (pod['cpu_request'] == 0 or 
            pod['cpu_limit'] == 0 or 
            pod['mem_request'] == 0 or 
            pod['mem_limit'] == 0)

def calculate_pod_resource_coverage(grouped_pods, ungrouped_pods):
    """Calculate pod counts by node type, including those missing resources"""
    # Structure: {node_type: {'total': int, 'without_resources': int}}
    by_node_type = defaultdict(lambda: {'total': 0, 'without_resources': 0})
    total_pods = 0
    pods_without_complete_config = 0

    # Check grouped pods (by node type)
    for node_data in grouped_pods.values():
        node_type = node_data['node_type']
        for pod in node_data['pods']:
            # Update global counts
            total_pods += 1
            # Update per-type counts
            by_node_type[node_type]['total'] += 1
            
            if has_missing_resources(pod):
                pods_without_complete_config += 1
                by_node_type[node_type]['without_resources'] += 1

    # Check ungrouped pods (special category)
    ungrouped_total = 0
    ungrouped_missing = 0
    for pod in ungrouped_pods:
        total_pods += 1
        ungrouped_total += 1
        
        if has_missing_resources(pod):
            pods_without_complete_config += 1
            ungrouped_missing += 1
    
    # Add ungrouped as a special "type"
    by_node_type['ungrouped'] = {
        'total': ungrouped_total,
        'without_resources': ungrouped_missing
    }

    return total_pods, pods_without_complete_config, by_node_type

def print_pod_resource_coverage(total_pods, pods_without, by_node_type):
    """Print summary of pod resource configuration with node type breakdown"""
    print("\n=== Pod Resource Configuration Analysis ===")
    if total_pods == 0:
        print("No pods found for resource configuration analysis")
        return

    # Overall summary
    overall_percentage = (pods_without / total_pods) * 100
    print(f"Overall Summary:")
    print(f"  Total pods analyzed: {total_pods}")
    print(f"  Pods missing at least one resource request or limit: {pods_without} ({overall_percentage:.2f}%)")
    print("\nBreakdown by Node Type:")
    print("-" * 40)
    print(f"{'Node Type':<15} {'Total Pods':<12} {'Missing Resources':<18} {'Percentage':<10}")
    print("-" * 40)

    # Print each node type's statistics
    for node_type in sorted(by_node_type.keys()):
        stats = by_node_type[node_type]
        if stats['total'] == 0:
            continue
            
        pct = (stats['without_resources'] / stats['total']) * 100
        print(f"{node_type:<15} {stats['total']:<12} {stats['without_resources']:<18} {pct:.2f}%")

    print("-" * 40)
    print("Note: A pod is considered incomplete if it lacks CPU requests, CPU limits, memory requests, or memory limits")

# ------------------------------
# Prometheus Alert functions
# ------------------------------
def get_prometheus_alerts():
    """Execute 'omc prom rules -s firing,pending -o json' and return parsed alert data"""
    try:
        result = subprocess.run(
            ["omc", "prom", "rules", "-s", "firing,pending", "-o", "json"],
            capture_output=True,
            text=True,
            check=True
        )
        
        if not result.stdout:
            print("Alert command executed successfully but returned no data")
            return None
        
        return json.loads(result.stdout)
        
    except subprocess.CalledProcessError as e:
        print(f"Alert command failed with return code: {e.returncode}")
        print(f"Error output: {e.stderr}")
        return None
    except json.JSONDecodeError as e:
        print(f"Alert JSON parsing failed: {e}")
        print(f"Raw alert output: {result.stdout}")
        return None
    except Exception as e:
        print(f"Unexpected error in alert retrieval: {e}")
        return None

def count_alerts_by_severity(alert_data):
    """Count alerts by severity (critical, warning, and other)"""
    counts = {
        'critical': 0,
        'warning': 0,
        'other': 0,
        'total': 0
    }
    
    if not alert_data or 'data' not in alert_data or not isinstance(alert_data['data'], list):
        return counts
    
    for alert in alert_data['data']:
        counts['total'] += 1
        # Get severity label if present
        severity = alert.get('labels', {}).get('severity', '').lower()
        
        if severity == 'critical':
            counts['critical'] += 1
        elif severity == 'warning':
            counts['warning'] += 1
        else:
            counts['other'] += 1
    
    return counts

def print_alert_summary(counts):
    """Print summary of Prometheus alerts by severity"""
    print("\n=== Prometheus Alert Summary ===")
    if counts['total'] == 0:
        print("No firing or pending alerts found")
        return
    
    print(f"Total firing/pending alerts: {counts['total']}")
    print(f"  Critical: {counts['critical']} ({(counts['critical']/counts['total'])*100:.2f}%)")
    print(f"  Warning: {counts['warning']} ({(counts['warning']/counts['total'])*100:.2f}%)")
    print(f"  Other/Unknown severity: {counts['other']} ({(counts['other']/counts['total'])*100:.2f}%)")

# ------------------------------
# Data collection functions
# ------------------------------
def get_all_nodes():
    """Execute 'omc get node -o json' command and return parsed node data"""
    try:
        result = subprocess.run(
            ["omc", "get", "node", "-o", "json"],
            capture_output=True,
            text=True,
            check=True
        )
        
        if not result.stdout:
            print("Node command executed successfully but returned no data")
            return None
        
        return json.loads(result.stdout)
        
    except subprocess.CalledProcessError as e:
        print(f"Node command failed with return code: {e.returncode}")
        print(f"Error output: {e.stderr}")
        return None
    except json.JSONDecodeError as e:
        print(f"Node JSON parsing failed: {e}")
        print(f"Raw node output: {result.stdout}")
        return None
    except Exception as e:
        print(f"Unexpected error in node retrieval: {e}")
        return None

def get_all_pods():
    """Execute 'omc get pod -o json -A' command and return parsed pod data"""
    try:
        result = subprocess.run(
            ["omc", "get", "pod", "-o", "json", "-A"],
            capture_output=True,
            text=True,
            check=True
        )
        
        if not result.stdout:
            print("Pod command executed successfully but returned no data")
            return None
        
        return json.loads(result.stdout)
        
    except subprocess.CalledProcessError as e:
        print(f"Pod command failed with return code: {e.returncode}")
        print(f"Error output: {e.stderr}")
        return None
    except json.JSONDecodeError as e:
        print(f"Pod JSON parsing failed: {e}")
        print(f"Raw pod output: {result.stdout}")
        return None
    except Exception as e:
        print(f"Unexpected error in pod retrieval: {e}")
        return None

# ------------------------------
# Data processing functions
# ------------------------------
def create_node_info_map(node_data):
    """Create a mapping from node IP to node info (name + allocatable resources + node type + labels)"""
    node_info_map = {}  # {ip: {name, allocatable_cpu, allocatable_memory, allocatable_pods, node_type, labels}}
    
    if not node_data or 'items' not in node_data or not isinstance(node_data['items'], list):
        return node_info_map
        
    for node in node_data['items']:
        try:
            node_name = node['metadata']['name']
            node_ip = node['status']['addresses'][0]['address']
            labels = node.get('metadata', {}).get('labels', {})
            
            # Extract node type from labels (node-role.kubernetes.io/<nodetype>)
            node_type = "unknown"
            for label_key in labels:
                if label_key.startswith('node-role.kubernetes.io/'):
                    node_type = label_key.split('/')[-1]
                    break  # Take the first matching role label
            
            # Get and parse allocatable resources
            allocatable = node.get('status', {}).get('allocatable', {})
            allocatable_cpu = parse_cpu(allocatable.get('cpu', '0'))
            allocatable_memory = parse_memory(allocatable.get('memory', '0'))
            allocatable_pods = parse_pods(allocatable.get('pods', '0'))  # Parse pod count
            
            node_info_map[node_ip] = {
                'name': node_name,
                'node_type': node_type,
                'labels': labels,
                'allocatable_cpu': allocatable_cpu,
                'allocatable_memory': allocatable_memory,
                'allocatable_pods': allocatable_pods
            }
        except KeyError as e:
            print(f"Warning: Missing {e} field in node {node.get('metadata', {}).get('name', 'unknown')}, skipping")
        except IndexError:
            print(f"Warning: No addresses found for node {node.get('metadata', {}).get('name', 'unknown')}, skipping")
        except Exception as e:
            print(f"Error processing node {node.get('metadata', {}).get('name', 'unknown')}: {e}")
    
    return node_info_map

def group_pods_by_node(pod_data, node_info_map):
    """Group pods by node with resource calculations and allocatable info"""
    # Structure: {node_name: {'allocatable': {...}, 'node_type': ..., 'totals': {...}, 'pod_count': int, 'pods': [...]}}
    grouped_pods = {}
    ungrouped_pods = []
    
    if not pod_data or 'items' not in pod_data or not isinstance(pod_data['items'], list):
        return grouped_pods, ungrouped_pods
        
    for pod in pod_data['items']:
        try:
            # Basic pod info
            pod_namespace = pod['metadata']['namespace']
            pod_name = pod['metadata']['name']
            pod_host_ip = pod['status']['hostIP']
            
            # Initialize pod resource totals
            pod_cpu_request = 0.0
            pod_cpu_limit = 0.0
            pod_mem_request = 0
            pod_mem_limit = 0
            
            # Get containers and calculate resources
            containers = pod.get('spec', {}).get('containers', [])
            for container in containers:
                resources = container.get('resources', {})
                requests = resources.get('requests', {})
                limits = resources.get('limits', {})
                
                # Accumulate container resources to pod totals
                pod_cpu_request += parse_cpu(requests.get('cpu'))
                pod_cpu_limit += parse_cpu(limits.get('cpu'))
                pod_mem_request += parse_memory(requests.get('memory'))
                pod_mem_limit += parse_memory(limits.get('memory'))
            
            # Prepare pod info with resources
            pod_info = {
                'namespace': pod_namespace,
                'name': pod_name,
                'cpu_request': pod_cpu_request,
                'cpu_limit': pod_cpu_limit,
                'mem_request': pod_mem_request,
                'mem_limit': pod_mem_limit
            }
            
            # Add to appropriate node group
            if pod_host_ip in node_info_map:
                node_info = node_info_map[pod_host_ip]
                node_name = node_info['name']
                
                # Initialize node entry if not exists
                if node_name not in grouped_pods:
                    grouped_pods[node_name] = {
                        'node_type': node_info['node_type'],
                        'allocatable': {
                            'cpu': node_info['allocatable_cpu'],
                            'memory': node_info['allocatable_memory'],
                            'pods': node_info['allocatable_pods']
                        },
                        'totals': {
                            'cpu_request': 0.0,
                            'cpu_limit': 0.0,
                            'mem_request': 0,
                            'mem_limit': 0
                        },
                        'pod_count': 0,
                        'pods': []
                    }
                
                # Add pod to node and update totals
                grouped_pods[node_name]['pods'].append(pod_info)
                grouped_pods[node_name]['pod_count'] += 1
                grouped_pods[node_name]['totals']['cpu_request'] += pod_cpu_request
                grouped_pods[node_name]['totals']['cpu_limit'] += pod_cpu_limit
                grouped_pods[node_name]['totals']['mem_request'] += pod_mem_request
                grouped_pods[node_name]['totals']['mem_limit'] += pod_mem_limit
            else:
                ungrouped_pods.append(pod_info)
                
        except KeyError as e:
            print(f"Warning: Missing {e} field in pod {pod.get('metadata', {}).get('name', 'unknown')}, skipping")
        except Exception as e:
            print(f"Error processing pod {pod.get('metadata', {}).get('name', 'unknown')}: {e}")
    
    return grouped_pods, ungrouped_pods

def aggregate_nodes_by_type_and_labels(node_data, grouped_pods, node_info_map):
    """Aggregate all node types by their type first, then by common labels (excluding specified labels)"""
    # Structure: {node_type: {label_key: group_data}}
    type_groups = defaultdict(lambda: defaultdict(list))
    
    if not node_data or 'items' not in node_data or not isinstance(node_data['items'], list):
        return type_groups
    
    for node in node_data['items']:
        try:
            node_name = node['metadata']['name']
            # Get node info to check type
            node_ip = node['status']['addresses'][0]['address']
            if node_ip not in node_info_map:
                continue
                
            node_info = node_info_map[node_ip]
            node_type = node_info['node_type']
                
            # Get labels and remove excluded labels
            labels = node.get('metadata', {}).get('labels', {}).copy()
            # Exclude specified labels
            labels.pop('kubernetes.io/hostname', None)
            labels.pop('node.name', None)
            labels.pop('twistlock-defender', None)
            
            # Create a hashable key from labels (sorted tuples)
            label_key = tuple(sorted(labels.items()))
            type_groups[node_type][label_key].append(node_name)
            
        except (KeyError, IndexError) as e:
            print(f"Warning: Skipping node {node.get('metadata', {}).get('name', 'unknown')} during aggregation: {e}")
        except Exception as e:
            print(f"Error aggregating node {node.get('metadata', {}).get('name', 'unknown')}: {e}")
    
    # Calculate aggregated resources for each group
    aggregated_results = defaultdict(dict)
    for node_type, label_groups in type_groups.items():
        for label_key, node_names in label_groups.items():
            # Convert label key back to dictionary
            common_labels = dict(label_key)
            
            # Initialize aggregates
            total_nodes = len(node_names)
            total_allocatable_cpu = 0.0
            total_allocatable_memory = 0
            total_allocatable_pods = 0
            total_cpu_request = 0.0
            total_cpu_limit = 0.0
            total_mem_request = 0
            total_mem_limit = 0
            total_pod_count = 0
            
            # Sum resources across all nodes in the group
            for node_name in node_names:
                if node_name in grouped_pods:
                    node_data = grouped_pods[node_name]
                    # Allocatable resources
                    total_allocatable_cpu += node_data['allocatable']['cpu']
                    total_allocatable_memory += node_data['allocatable']['memory']
                    total_allocatable_pods += node_data['allocatable']['pods']
                    # Pod resources
                    total_cpu_request += node_data['totals']['cpu_request']
                    total_cpu_limit += node_data['totals']['cpu_limit']
                    total_mem_request += node_data['totals']['mem_request']
                    total_mem_limit += node_data['totals']['mem_limit']
                    total_pod_count += node_data['pod_count']
            
            aggregated_results[node_type][label_key] = {
                'common_labels': common_labels,
                'node_count': total_nodes,
                'nodes': node_names,
                'allocatable': {
                    'cpu': total_allocatable_cpu,
                    'memory': total_allocatable_memory,
                    'pods': total_allocatable_pods
                },
                'totals': {
                    'cpu_request': total_cpu_request,
                    'cpu_limit': total_cpu_limit,
                    'mem_request': total_mem_request,
                    'mem_limit': total_mem_limit,
                    'pod_count': total_pod_count
                }
            }
    
    return aggregated_results

def print_aggregated_nodes(aggregated_results):
    """Print aggregated node information grouped by node type and common labels"""
    print("\n=== Aggregated Nodes by Type and Common Labels ===")
    
    if not aggregated_results:
        print("No nodes found for aggregation")
        return
    
    for node_type, label_groups in aggregated_results.items():
        print(f"\nNode Type: {node_type}")
        print("-" * (len(node_type) + 11))  # Underline the type header
        
        for i, (_, group_data) in enumerate(label_groups.items(), 1):
            print(f"\n  Group {i}:")
            print(f"    Number of nodes: {group_data['node_count']}")
            print("    Common labels:")
            for label, value in group_data['common_labels'].items():
                print(f"      {label}: {value}")
            print("    Nodes in group:")
            for node_name in group_data['nodes']:
                print(f"      - {node_name}")
            
            print("    Aggregated Allocatable Resources:")
            print(f"      Total CPU: {group_data['allocatable']['cpu']:.3f} cores")
            print(f"      Total Memory: {format_memory(group_data['allocatable']['memory'])}")
            print(f"      Total Pod Capacity: {group_data['allocatable']['pods']} pods")
            
            print("    Aggregated Usage:")
            # CPU calculations
            cpu_request_pct = calculate_percentage(
                group_data['totals']['cpu_request'],
                group_data['allocatable']['cpu']
            )
            cpu_limit_pct = calculate_percentage(
                group_data['totals']['cpu_limit'],
                group_data['allocatable']['cpu']
            )
            print(f"      CPU Requests: {group_data['totals']['cpu_request']:.3f} cores ({cpu_request_pct} of allocatable)")
            print(f"      CPU Limits: {group_data['totals']['cpu_limit']:.3f} cores ({cpu_limit_pct} of allocatable)")
            
            # Memory calculations
            mem_request_pct = calculate_percentage(
                group_data['totals']['mem_request'],
                group_data['allocatable']['memory']
            )
            mem_limit_pct = calculate_percentage(
                group_data['totals']['mem_limit'],
                group_data['allocatable']['memory']
            )
            print(f"      Memory Requests: {format_memory(group_data['totals']['mem_request'])} ({mem_request_pct} of allocatable)")
            print(f"      Memory Limits: {format_memory(group_data['totals']['mem_limit'])} ({mem_limit_pct} of allocatable)")
            
            # Pod count calculations
            pod_pct = calculate_percentage(
                group_data['totals']['pod_count'],
                group_data['allocatable']['pods']
            )
            print(f"      Pod Count: {group_data['totals']['pod_count']} pods ({pod_pct} of capacity)")

def print_pods_with_resources(grouped_pods, ungrouped_pods, show_pods=False):
    """Print pods grouped by node with resource summary, including pod count utilization"""
    print("\n=== Node Resource Utilization Summary ===")
    
    # Print grouped pods
    if grouped_pods:
        for node_name, data in grouped_pods.items():
            print(f"\nNode: {node_name} (Type: {data['node_type']})")
            
            # Allocatable resources
            print("  Allocatable Resources:")
            print(f"    CPU: {data['allocatable']['cpu']:.3f} cores")
            print(f"    Memory: {format_memory(data['allocatable']['memory'])}")
            print(f"    Max Pods: {data['allocatable']['pods']}")
            
            # Total requests/limits with percentages
            print("  Total Usage:")
            # CPU calculations
            cpu_request_pct = calculate_percentage(
                data['totals']['cpu_request'], 
                data['allocatable']['cpu']
            )
            cpu_limit_pct = calculate_percentage(
                data['totals']['cpu_limit'], 
                data['allocatable']['cpu']
            )
            print(f"    CPU Requests: {data['totals']['cpu_request']:.3f} cores ({cpu_request_pct} of allocatable)")
            print(f"    CPU Limits: {data['totals']['cpu_limit']:.3f} cores ({cpu_limit_pct} of allocatable)")
            
            # Memory calculations
            mem_request_pct = calculate_percentage(
                data['totals']['mem_request'], 
                data['allocatable']['memory']
            )
            mem_limit_pct = calculate_percentage(
                data['totals']['mem_limit'], 
                data['allocatable']['memory']
            )
            print(f"    Memory Requests: {format_memory(data['totals']['mem_request'])} ({mem_request_pct} of allocatable)")
            print(f"    Memory Limits: {format_memory(data['totals']['mem_limit'])} ({mem_limit_pct} of allocatable)")
            
            # Pod count calculation
            pod_pct = calculate_percentage(
                data['pod_count'], 
                data['allocatable']['pods']
            )
            print(f"    Pods: {data['pod_count']} running ({pod_pct} of capacity)")
            
            # Print pod list only if enabled
            if show_pods and data['pods']:
                print("  Pod List:")
                for pod in data['pods']:
                    print(f"    - {pod['namespace']}/{pod['name']}")
    else:
        print("\nNo pods were successfully grouped by node")
    
    # Print ungrouped pods if enabled
    if show_pods and ungrouped_pods:
        print("\n=== Ungrouped Pods (could not match to a node) ===")
        for pod in ungrouped_pods:
            print(f"  - {pod['namespace']}/{pod['name']}")

# ------------------------------
# Main execution
# ------------------------------
if __name__ == "__main__":
    # Parse command line arguments
    parser = argparse.ArgumentParser(description='Kubernetes Node and Pod Resource Analyzer')
    parser.add_argument('--show-pods', action='store_true', 
                      help='Show individual pod lists (disabled by default)')
    args = parser.parse_args()

    # Get node data and create info map
    print("Retrieving node information...")
    node_data = get_all_nodes()
    
    if not node_data:
        print("Failed to retrieve valid node data - cannot proceed")
    else:
        print("Successfully retrieved node data")
        node_info_map = create_node_info_map(node_data)
        print(f"Created node info mapping for {len(node_info_map)} nodes")

        # Get pod data and group by node
        print("\nRetrieving pod information...")
        pod_data = get_all_pods()
        
        if pod_data:
            print("Successfully retrieved pod data")
            grouped_pods, ungrouped_pods = group_pods_by_node(pod_data, node_info_map)
            print_pods_with_resources(grouped_pods, ungrouped_pods, args.show_pods)
            
            # Add pod resource configuration analysis with node type breakdown
            total_pods, pods_without, by_node_type = calculate_pod_resource_coverage(grouped_pods, ungrouped_pods)
            print_pod_resource_coverage(total_pods, pods_without, by_node_type)
            
            # Add aggregated nodes section (all types)
            aggregated_results = aggregate_nodes_by_type_and_labels(node_data, grouped_pods, node_info_map)
            print_aggregated_nodes(aggregated_results)
            
            # Add Prometheus alert analysis
            print("\nRetrieving Prometheus alert information...")
            alert_data = get_prometheus_alerts()
            if alert_data:
                alert_counts = count_alerts_by_severity(alert_data)
                print_alert_summary(alert_counts)
            else:
                print("Failed to retrieve or process Prometheus alert data")
        else:
            print("Failed to retrieve valid pod data")
    
