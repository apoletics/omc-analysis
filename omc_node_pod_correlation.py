import subprocess
import json

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

def create_node_ip_to_name_map(node_data):
    """Create a mapping from node IP (status.addresses[0].address) to node name"""
    node_ip_map = {}
    
    if not node_data or 'items' not in node_data or not isinstance(node_data['items'], list):
        return node_ip_map
        
    for node in node_data['items']:
        try:
            # Get node name
            node_name = node['metadata']['name']
            # Get node IP from first address entry
            node_ip = node['status']['addresses'][0]['address']
            node_ip_map[node_ip] = node_name
        except KeyError as e:
            print(f"Warning: Missing {e} field in node {node.get('metadata', {}).get('name', 'unknown')}, skipping")
        except IndexError:
            print(f"Warning: No addresses found for node {node.get('metadata', {}).get('name', 'unknown')}, skipping")
        except Exception as e:
            print(f"Error processing node {node.get('metadata', {}).get('name', 'unknown')}: {e}")
    
    return node_ip_map

def group_pods_by_node(pod_data, node_ip_map):
    """Group pods by their corresponding node using hostIP correlation"""
    grouped_pods = {}
    ungrouped_pods = []  # For pods that couldn't be matched to a node
    
    if not pod_data or 'items' not in pod_data or not isinstance(pod_data['items'], list):
        return grouped_pods, ungrouped_pods
        
    for pod in pod_data['items']:
        try:
            # Get pod basic info
            pod_namespace = pod['metadata']['namespace']
            pod_name = pod['metadata']['name']
            pod_host_ip = pod['status']['hostIP']
            
            # Find corresponding node name
            if pod_host_ip in node_ip_map:
                node_name = node_ip_map[pod_host_ip]
                # Add to grouped pods
                if node_name not in grouped_pods:
                    grouped_pods[node_name] = []
                grouped_pods[node_name].append((pod_namespace, pod_name))
            else:
                ungrouped_pods.append((pod_host_ip, pod_namespace, pod_name))
                
        except KeyError as e:
            print(f"Warning: Missing {e} field in pod {pod.get('metadata', {}).get('name', 'unknown')}, skipping")
        except Exception as e:
            print(f"Error processing pod {pod.get('metadata', {}).get('name', 'unknown')}: {e}")
    
    return grouped_pods, ungrouped_pods

def print_pods_grouped_by_node(grouped_pods, ungrouped_pods):
    """Print pods grouped by their node, followed by ungrouped pods"""
    print("\n=== Pods Grouped by Node ===")
    
    # Print grouped pods
    if grouped_pods:
        for node_name, pods in grouped_pods.items():
            print(f"\nNode: {node_name}")
            print("  Pods:")
            for namespace, pod_name in pods:
                print(f"  - {namespace}/{pod_name}")
    else:
        print("\nNo pods were successfully grouped by node")
    
    # Print ungrouped pods if any
    if ungrouped_pods:
        print("\n=== Ungrouped Pods (could not match to a node) ===")
        for host_ip, namespace, pod_name in ungrouped_pods:
            print(f"Host IP: {host_ip} - {namespace}/{pod_name}")

if __name__ == "__main__":
    # First, get node data
    print("Retrieving node information...")
    node_data = get_all_nodes()
    
    if not node_data:
        print("Failed to retrieve valid node data - cannot proceed with pod grouping")
    else:
        print("Successfully retrieved node data")
        # Create mapping from node IP to node name
        node_ip_map = create_node_ip_to_name_map(node_data)
        print(f"Created node IP mapping for {len(node_ip_map)} nodes")

        # Then, get pod data
        print("\nRetrieving pod information...")
        pod_data = get_all_pods()
        
        if pod_data:
            print("Successfully retrieved pod data")
            # Group pods by node
            grouped_pods, ungrouped_pods = group_pods_by_node(pod_data, node_ip_map)
            # Print the results
            print_pods_grouped_by_node(grouped_pods, ungrouped_pods)
        else:
            print("Failed to retrieve valid pod data")
    
