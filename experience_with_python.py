from test_data import test_ips_ipv4, test_ipv6_addresses, test_cidr_ranges, test_ip_ranges, print_test_results
from itertools import product
import ipaddress

def validate_ip_addresses_python_lib(ip_list):
    """
    Validate a list of IP addresses and CIDR ranges using the ipaddress library.
    """
    # "3232235777",  # Numeric-only representation of 192.168.1.1 appears in the invalid list, even though it is valid
    # From my understanding you can't use the numeric representation of an IP address directly as a host IP, therefore the conversion would
    # to happen anyway.
    valid_entries = []
    invalid_entries = []

    for ip in ip_list:
        try:
            ipaddress.ip_address(ip)
            valid_entries.append(ip)
        except ValueError:
            try:
                ipaddress.ip_network(ip, strict=False)
                valid_entries.append(ip)
            except ValueError as e:
                invalid_entries.append((ip, str(e)))

    return valid_entries, invalid_entries

def expand_cidr_range(cidr):
    """
    Expand a CIDR range into a list of IPs using Python's ipaddress module.
    """
    try:
        network = ipaddress.ip_network(cidr, strict=False)
        expanded_ips = [str(ip) for ip in network.hosts()]
        return expanded_ips
    except ValueError as e:
        raise ValueError(f"Error expanding CIDR range {cidr}: {e}")

def expand_and_validate_ip_range(ip_range):
    # NO support for IPV6 Error processing range 2001:db8::[1:5]: Error processing IP range '2001:db8::[1:5]': invalid literal for int() with base 10: 'db8'
    """
    Expands IP ranges like '192.168.1.[1:5]' and validates them using Python's ipaddress module.
    """
    try:
        parts = ip_range.split('.')
        expanded_parts = []

        for part in parts:
            if '[' in part and ':' in part and ']' in part:
                range_start, range_end = map(int, part.strip('[]').split(':'))
                expanded_parts.append([str(i) for i in range(range_start, range_end + 1)])
            else:
                expanded_parts.append([part])

        expanded_ips = ['.'.join(ip) for ip in product(*expanded_parts)]

        valid_ips = []
        for ip in expanded_ips:
            try:
                ipaddress.ip_address(ip)
                valid_ips.append(ip)
            except ValueError:
                continue
        
        return valid_ips
    except Exception as e:
        raise ValueError(f"Error processing IP range '{ip_range}': {e}")

if __name__ == "__main__":
    valid_ips, invalid_ips = validate_ip_addresses_python_lib(test_ips_ipv4)
    print_test_results(valid_ips, invalid_ips, "IPv4 Validation (Python Library)")

    valid_ipv6, invalid_ipv6 = validate_ip_addresses_python_lib(test_ipv6_addresses)
    print_test_results(valid_ipv6, invalid_ipv6, "IPv6 Validation (Python Library)")

    for cidr in test_cidr_ranges:
        try:
            print(f"\nCIDR {cidr} expanded to: {expand_cidr_range(cidr)}")
        except ValueError as e:
            print(f"Error expanding CIDR {cidr}: {e}")

    for ip_range in test_ip_ranges:
        try:
            print(f"\nRange {ip_range} expanded to: {expand_and_validate_ip_range(ip_range)}")
        except ValueError as e:
            print(f"Error processing range {ip_range}: {e}")