import ipaddress
import re
from test_data import test_ips_ipv4, test_ipv6_addresses, test_cidr_ranges, print_test_results


def validate_ip_addresses(ip_list):
    """
    Validate a list of IP addresses, distinguishing between IPv4, IPv6, CIDR, and integer-based addresses.
    """
    valid_ipv4 = []
    valid_ipv6 = []
    valid_cidr = []
    invalid_ips = []

    for ip in ip_list:
        try:
            # Convert integer-like strings to actual integers before validation
            if ip.isdigit():
                ip = str(ipaddress.ip_address(int(ip)))  # Convert integer to IP string

            if is_valid_ipv4(ip):
                valid_ipv4.append(ip)
            elif is_valid_ipv6(ip):
                valid_ipv6.append(ip)
            elif is_valid_cidr(ip):
                valid_cidr.append(ip)
            else:
                invalid_ips.append((ip, "Invalid IP or CIDR format"))
        except ValueError as e:
            invalid_ips.append((ip, str(e)))

    return {
        "valid_ipv4": valid_ipv4,
        "valid_ipv6": valid_ipv6,
        "valid_cidr": valid_cidr,
        "invalid_ips": invalid_ips,
    }

def is_valid_ipv4(ip):
    """Checks if the input is a valid IPv4 address."""
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv4Address)
    except ValueError:
        return False

def is_valid_ipv6(ip):
    """Checks if the input is a valid IPv6 address."""
    try:
        return isinstance(ipaddress.ip_address(ip), ipaddress.IPv6Address)
    except ValueError:
        return False

def is_valid_cidr(ip):
    """Checks if the input is a valid CIDR notation (IPv4 or IPv6)."""
    try:
        ipaddress.ip_network(ip, strict=False)
        return True
    except ValueError:
        return False

def cidr_host_range(cidr):
    try:
        network = ipaddress.ip_network(cidr, strict=False)  # Create the network
        hosts = list(network.hosts())  # Get usable hosts
        return {"valid_hosts": [str(ip) for ip in hosts], "invalid_ips": []}
    except ValueError as e:
        return {"valid_hosts": [], "invalid_ips": [str(cidr)]}

def is_valid_hostname(hostname):
    """
    Validate if the given hostname follows standard domain name rules.

    This function checks:
    - The hostname is not empty and does not exceed 253 characters.
    - Each label (separated by dots) is between 1 and 63 characters.
    - Labels contain only letters, numbers, or hyphens but do not start or end with a hyphen.

    Note: **This function does NOT verify if the hostname has a valid Top-Level Domain (TLD)**.
          It only ensures the structure follows DNS naming rules.
    """    
    # Ensure hostname is not empty and within valid length
    if len(hostname) > 253 or len(hostname.strip()) == 0:
        return False
    
    # Split hostname into labels
    labels = hostname.split(".")
    
    # Validate each label
    for label in labels:
        if len(label) > 63 or len(label) == 0:
            return False
        # Labels must match this regex: only letters, numbers, hyphens, not start or end with hyphen
        if not re.match(r"^[a-zA-Z0-9-]+$", label) or label.startswith("-") or label.endswith("-"):
            return False
    
    return True

if __name__ == "__main__":

    print("IPv4 Validation:")
    print(validate_ip_addresses(test_ips_ipv4))

    print("IPv6 Validation:")
    print(validate_ip_addresses(test_ipv6_addresses))

    print("CIDR Validation:")
    print(validate_ip_addresses(test_cidr_ranges))  

    for cidr in test_cidr_ranges:
        print(cidr_host_range(cidr))              
