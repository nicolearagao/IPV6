import re
from ansible_collections.ansible.utils.plugins.filter.usable_range import _usable_range
from ansible_collections.ansible.utils.plugins.filter.ipaddr import ipaddr
from ansible_collections.community.general.plugins.test.fqdn_valid import fqdn_valid
from ansible.plugins.inventory import BaseInventoryPlugin
from ansible.errors import AnsibleError
from test_data import test_ips_ipv4, test_ipv6_addresses, test_cidr_ranges, print_test_results


def cidr_host_range(cidr):
    """
    Generate a list of host-usable IPs from a CIDR using Ansible's usable_range filter.
    Filters out network and broadcast addresses.
    """
    try:
        # Get the full range of IPs (including network and broadcast)
        range_data = _usable_range(cidr)
        all_ips = range_data.get("usable_ips", [])

        # Ensure we have valid IPs
        if not all_ips:
            return {"valid_hosts": [], "invalid_ips": [cidr]}

        # Identify network and broadcast addresses
        if ipaddr(cidr, 'ipv4'):
            network_addr = ipaddr(cidr, 'network')
            broadcast_addr = ipaddr(cidr, 'broadcast')

            # Remove network and broadcast from the list
            host_ips = [ip for ip in all_ips if ip not in (network_addr, broadcast_addr)]
        elif ipaddr(cidr, 'ipv6'):
            # IPv6 generally doesn't have a "broadcast", but let's remove the first address if it's an all-zero identifier
            network_addr = ipaddr(cidr, 'network')
            host_ips = [ip for ip in all_ips if ip not in (network_addr)]
        else:
            host_ips = all_ips

        return {
            "valid_hosts": host_ips,
            "invalid_ips": []
        }

    except Exception as e:
        return {
            "valid_hosts": [],
            "invalid_ips": [str(e)]
        }
    
def validate_ip_addresses(ip_list):
    """
    Validate a list of IP addresses using Ansible's ipaddr filter.
    Distinguishes between IPv4, IPv6, and CIDR networks while allowing integer-based addresses.
    """
    valid_ipv4 = []
    valid_ipv6 = []
    valid_cidr = []
    invalid_ips = []

    for ip in ip_list:
        try:
            # Check if input is an integer and convert it after validation
            converted_ip = convert_integer_ip(ip) if ip.isdigit() else ip

            if is_valid_cidr(converted_ip):
                valid_cidr.append(converted_ip)        
            elif is_valid_ipv4(converted_ip):
                valid_ipv4.append(converted_ip)
            elif is_valid_ipv6(converted_ip):
                valid_ipv6.append(converted_ip)
            else:
                invalid_ips.append((ip, "Invalid IP or CIDR format"))

        except Exception as e:
            invalid_ips.append((ip, str(e)))

    return {
        "valid_ipv4": valid_ipv4,
        "valid_ipv6": valid_ipv6,
        "valid_cidr": valid_cidr,
        "invalid_ips": invalid_ips,
    }

def is_valid_ipv4(ip):
    """Checks if the input is a valid IPv4 address."""
    return bool(ipaddr(ip, "ipv4"))

def is_valid_ipv6(ip):
    """Checks if the input is a valid IPv6 address."""
    return bool(ipaddr(ip, "ipv6"))

def is_valid_cidr(ip):
    """Checks if the input is a valid CIDR notation (IPv4 or IPv6)."""
    return bool(ipaddr(ip, "net"))

def convert_integer_ip(ip):
    """Converts an integer-based IP representation into a standard IP address string."""
    return str(ipaddr(int(ip), "address"))

def is_valid_fqdn(hostname, min_labels=1, allow_underscores=False):
    """
    Validate FQDN based on RFC 1123 and additional options.
    
    :param hostname: The hostname to validate.
    :param min_labels: Minimum required labels (separated by dots).
    :param allow_underscores: Whether to allow underscores in hostnames.
    :return: True if valid, False otherwise.
    """
    if not allow_underscores and "_" in hostname:
        return False

    if fqdn_valid(hostname, allow_underscores=allow_underscores):
        return hostname.count('.') >= (min_labels - 1)
    
    return False


class AnsibleHostRangeValidator:
    """
    Adapter for Ansible's host range validation.
    Provides a stable interface for checking Ansible-style host ranges.
    """

    def __init__(self):
        self.plugin = BaseInventoryPlugin()

    def is_valid_range(self, value: str) -> bool:
        """Validate an Ansible host range without expanding it."""
        try:
            self.plugin._expand_hostpattern(value)  # Will throw an error if invalid
            return True
        except ValueError as ve:
            print(f"[ERROR] Invalid host range format: {value} - {ve}")
        except AnsibleError as ae:
            print(f"[ERROR] Ansible-specific error for {value}: {ae}")
        except Exception as e:
            print(f"[ERROR] Unexpected error validating {value}: {e}")
        return False  # If any error occurs, return False



if __name__ == "__main__":

    print("IPv4 Validation:")
    print(validate_ip_addresses(test_ips_ipv4))

    print("IPv6 Validation:")
    print(validate_ip_addresses(test_ipv6_addresses))

    print("CIDR Validation:")
    print(validate_ip_addresses(test_cidr_ranges))
    
    # for cidr in test_cidr_ranges:
    #     print(cidr_host_range(cidr))

    # print(is_valid_fqdn("example.com"))
    # print(is_valid_fqdn("my_server.example.com", allow_underscores=True))
    # print(is_valid_fqdn("invalid_hostname_with_underscore.com"))
    # print(is_valid_fqdn("singlelabel", min_labels=2))

    # validator = AnsibleHostRangeValidator()

    # print(validator.is_valid_range("host[1:10]"))
    # print(validator.is_valid_range("server[01:09]"))
    # print(validator.is_valid_range("node[5:2]"))
    # print(validator.is_valid_range("invalid[1:]"))
    # print(validator.is_valid_range("node[a:10]"))