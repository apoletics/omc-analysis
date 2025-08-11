import subprocess
import json

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
            # Convert millicores to cores
            return float(cpu_str[:-1]) / 1000.0
        else:
            # Assume value is in cores
            return float(cpu_str)
    except (ValueError, TypeError):
        return 0.0

def parse_memory(mem_value):
    """Parse memory value (handles common Kubernetes units)"""
    if not mem_value:
        return 0
    mem_str = str(mem_value).strip().lower()
    memory_units = {
        'k': 1000,
        'm': 1000**2,
        'g': 1000**3,
        't': 1000**4,
        'p': 1000**5,
        'e': 1000**6,
        'ki': 1024,
        'mi': 1024**2,
        'gi': 1024**3,
        'ti': 1024**4,
        'pi': 1024**5,
        'ei': 1024**6,
    }

    # Extract unit and numeric part
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

def format_memory(bytes_value):
    """Convert bytes to human-readable format"""
    if bytes_value == 0:
        return "0"
    units = [
        ('Ei', 1024**6),
        ('Pi', 1024**5),
        ('Ti', 1024**4),
        ('Gi', 1024**3),
        ('Mi', 1024**2),
        ('Ki', 1024),
        ('B', 1)
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
    """Create a mapping from node IP to node info (name + allocatable resources)"""
    node_info_map = {}  # {ip: {name, allocatable_cpu, allocatable_memory}}
    
    if not node_data or 'items' not in node_data or not isinstance(node_data['items'], list):
        return node_info_map
        
    for node in node_data['items']:
        try:
            node_name = node['metadata']['name']
            node_ip = node['status']['addresses'][0]['address']
            
            # Get and parse allocatable resources
            allocatable = node.get('status', {}).get('allocatable', {})
            allocatable_cpu = parse_cpu(allocatable.get('cpu', '0'))
            allocatable_memory = parse_memory(allocatable.get('memory', '0'))
            
            node_info_map[node_ip] = {
                'name': node_name,
                'allocatable_cpu': allocatable_cpu,
                'allocatable_memory': allocatable_memory
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
    # Structure: {node_name: {'allocatable': {...}, 'totals': {...}, 'pods': [...]}}
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
                        'allocatable': {
                            'cpu': node_info['allocatable_cpu'],
                            'memory': node_info['allocatable_memory']
                        },
                        'totals': {
                            'cpu_request': 0.0,
                            'cpu_limit': 0.0,
                            'mem_request': 0,
                            'mem_limit': 0
                        },
                        'pods': []
                    }
                
                # Add pod to node and update totals
                grouped_pods[node_name]['pods'].append(pod_info)
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

def print_pods_with_resources(grouped_pods, ungrouped_pods):
    """Print pods grouped by node with resource summary, allocatable resources, and percentages"""
    print("\n=== Pods Grouped by Node with Resource Utilization ===")
    
    # Print grouped pods
    if grouped_pods:
        for node_name, data in grouped_pods.items():
            print(f"\nNode: {node_name}")
            
            # Allocatable resources
            print("  Allocatable Resources:")
            print(f"    CPU: {data['allocatable']['cpu']:.3f} cores")
            print(f"    Memory: {format_memory(data['allocatable']['memory'])}")
            
            # Total requests/limits with percentages
            print("  Total Pod Resources:")
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
            
            # Individual pods
            print("  Pods:")
            for pod in data['pods']:
                print(f"    - {pod['namespace']}/{pod['name']}")
                print(f"        CPU Request: {pod['cpu_request']:.3f} cores | Limit: {pod['cpu_limit']:.3f} cores")
                print(f"        Memory Request: {format_memory(pod['mem_request'])} | Limit: {format_memory(pod['mem_limit'])}")
    else:
        print("\nNo pods were successfully grouped by node")
    
    # Print ungrouped pods if any
    if ungrouped_pods:
        print("\n=== Ungrouped Pods (could not match to a node) ===")
        for pod in ungrouped_pods:
            print(f"  - {pod['namespace']}/{pod['name']}")
            print(f"      CPU Request: {pod['cpu_request']:.3f} cores | Limit: {pod['cpu_limit']:.3f} cores")
            print(f"      Memory Request: {format_memory(pod['mem_request'])} | Limit: {format_memory(pod['mem_limit'])}")

# ------------------------------
# Main execution
# ------------------------------
if __name__ == "__main__":
    # Get node data and create info map (includes allocatable resources)
    print("Retrieving node information...")
    node_data = get_all_nodes()
    
    if not node_data:
        print("Failed to retrieve valid node data - cannot proceed with pod grouping")
    else:
        print("Successfully retrieved node data")
        node_info_map = create_node_info_map(node_data)
        print(f"Created node info mapping for {len(node_info_map)} nodes")

        # Get pod data and group by node with resources
        print("\nRetrieving pod information...")
        pod_data = get_all_pods()
        
        if pod_data:
            print("Successfully retrieved pod data")
            grouped_pods, ungrouped_pods = group_pods_by_node(pod_data, node_info_map)
            print_pods_with_resources(grouped_pods, ungrouped_pods)
        else:
            print("Failed to retrieve valid pod data")
    
