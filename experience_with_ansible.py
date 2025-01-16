import re
from test_data import test_ips_ipv4, test_ipv6_addresses, test_cidr_ranges_ipv4, test_cidr_ranges_ipv6, print_test_results
from ansible_collections.ansible.utils.plugins.filter.ipaddr import ipaddr

def validate_ip_addresses(ip_list):
    """
    Validate a list of IP addresses using Ansible's ipaddr filter.
    """
    valid_ips = []
    invalid_ips = []

    for ip in ip_list:
        try:
            result = ipaddr(ip)
            if result:
                valid_ips.append(ip)
            else:
                invalid_ips.append((ip, "Invalid IP address"))
        except Exception as e:
            invalid_ips.append((ip, str(e)))

    return valid_ips, invalid_ips

def validate_and_generate_ansible_range_ipv4(cidr):
    """
    Validate a CIDR range and generate an Ansible-compatible range.
    Supports IPv4 CIDR ranges and produces ranges like '192.168.0.[0:255]'.
    """
    try:
        # Ensure the input is a valid IPv4 network
        if not ipaddr(cidr, query="ipv4"):
            raise ValueError(f"Invalid or non-IPv4 CIDR range: {cidr}")

        # Validate and get the usable range
        ip_range = ipaddr(cidr, query="range_usable")
        if not ip_range:
            raise ValueError(f"Invalid CIDR range: {cidr}")

        # Split into start and end IPs
        start_ip, end_ip = ip_range.split("-")
        start_parts, end_parts = start_ip.split("."), end_ip.split(".")
        prefix_bits = int(ipaddr(cidr, query="prefix"))

        ansible_out = []
        for i in range(4):
            # Determine the number of bits to process for this octet
            remaining_bits = prefix_bits - i * 8

            if remaining_bits <= 0:
                # No bits left to preserve, full range for this octet
                ansible_out.append("[0:255]")
            elif remaining_bits >= 8:
                # All bits of this octet are fixed
                ansible_out.append(start_parts[i])
            else:
                # Partially fixed octet: calculate range
                _validate_octet_bits(remaining_bits)
                mask = -1 << (8 - remaining_bits)
                lower_bound = int(start_parts[i]) & mask
                upper_bound = lower_bound + ~mask
                ansible_out.append(f"[{lower_bound}:{upper_bound}]")
        return ".".join(ansible_out)
    except Exception as e:
        raise ValueError(f"Error processing CIDR range '{cidr}': {e}")


def _validate_octet_bits(this_octet_bits):
    """Ensure the number of preserved bits in an octet is valid."""
    if not (0 <= this_octet_bits <= 8):  # Allow 0 for full ranges
        raise ValueError(f"Invalid value for this_octet_bits={this_octet_bits}")


def expand_ipv6_cidr_range(cidr, max_ips=256):
    """
    Expand an IPv6 CIDR range into a list of all valid IPs using the Ansible ipaddr filter.
    Enforces a maximum limit on the number of IPs to expand.
    """
    try:
        # Ensure the input is a valid IPv6 CIDR
        if ':' not in cidr or not ipaddr(cidr, query='net'):
            raise ValueError(f"Invalid IPv6 CIDR range: {cidr}")

        # Get the usable range of IPs in the CIDR
        ip_range = ipaddr(cidr, query='range_usable')
        if not ip_range:
            raise ValueError(f"Invalid or unusable IPv6 CIDR range: {cidr}")

        # Split into start and end IPs
        start_ip, end_ip = ip_range.split('-')

        # Convert start and end IPs to integers
        start = int(ipaddr(start_ip, query='int'))
        end = int(ipaddr(end_ip, query='int'))

        # Calculate the number of IPs
        total_ips = end - start + 1
        if total_ips > max_ips:
            raise ValueError(
                f"Cannot expand CIDR '{cidr}' with {total_ips} IPs. "
                f"Limit is {max_ips}."
            )

        # Generate the list of IPs
        expanded_ips = [
            str(ipaddr(i, query='ipv6')) for i in range(start, end + 1)
        ]

        return expanded_ips

    except Exception as e:
        raise ValueError(f"Error processing IPv6 CIDR range '{cidr}': {e}")

def is_valid_hostname(hostname):
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
    valid_ips, invalid_ips = validate_ip_addresses(test_ips_ipv4)
    print_test_results(valid_ips, invalid_ips, "IPv4 Validation (Ansible)")

    valid_ipv6, invalid_ipv6 = validate_ip_addresses(test_ipv6_addresses)
    print_test_results(valid_ipv6, invalid_ipv6, "IPv6 Validation (Ansible)")

    for cidr in test_cidr_ranges_ipv6:
        try:
            print(f"\nCIDR {cidr} expanded to: {expand_ipv6_cidr_range(cidr)}")
        except ValueError as e:
            print(f"Error expanding CIDR {cidr}: {e}")

    for cidr in test_cidr_ranges_ipv4:
        try:
            print(f"\nCIDR {cidr} expanded to: {validate_and_generate_ansible_range_ipv4(cidr)}")
        except ValueError as e:
            print(f"Error expanding CIDR {cidr}: {e}")


    print(is_valid_hostname("example.com"))         # True
    print(is_valid_hostname("192.2.2.com"))         # True
    print(is_valid_hostname("banana.com"))          # True
    print(is_valid_hostname("-invalid-.com"))       # False
    print(is_valid_hostname("toolonglabel"*10+".com")) # False
    print(is_valid_hostname("invalid..com"))        # False
    print(is_valid_hostname(".invalid.com"))        # False
    print(is_valid_hostname("invalid.com."))        # False

