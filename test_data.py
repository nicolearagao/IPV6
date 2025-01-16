# test_data.py

test_ips_ipv4 = [
    "192.168.1.1", "10.0.0.1", "127.0.0.1",  # Valid
    "192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12",  # Valid CIDRs
    "127.1", "127.65530",  # Valid compressed notation
    "169.254.1.1", "192.0.2.0", "198.51.100.0",  # Reserved
    "3232235777", "0xC0A80101", "0300.0250.0001.0001", "192.168.001.001",  # Non-standard formats
    "256.256.256.256", "192.168.1", "192.168.1.1.", ".192.168.1.1",  # Invalid cases
    "192..168.1.1", "192.168.a.1", "192.168.1.0/33", "192.168.1.0/-1",
    "", "None", "192.168.1.255", "192.168.0.0"
]

test_ipv6_addresses = [
    "2001:0db8:85a3:0000:0000:8a2e:0370:7334",  # Fully defined
    "2001:0DB8:85a3:0000:0000:8a2E:0370:7334",  # Case-insensitive
    "2001:db8:85a3::8a2e:370:7334",  # Compressed
    "2001:db8:1234::/48", "2001:db8::/32", "ff00::/8", "::/128", "fe80::/10",  # Valid CIDRs
    "::ffff:192.0.2.128", "2001:0db8:0000:0000:0000:0000:0000:0001",  # Special cases
    "2001:db8:::1", "2001:db8::85a3::8a2e:370:7334",  # Invalid cases
    "2001:db8:85a3:0:0:8a2e:370", "2001:db8:85a3:0:0:8a2e:370:g",
    "2001:db8:85a3:0:0:8a2e:370:123456", "12345::abcd",
    "2001:db8::/129", "fe80::1/130",
    "2001:db8:85a3:0:0:8a2e:370:7334", # valid, with leading zeros dropped
    "2001:db8:85a3:0:0:8a2e:370:73340000" # invalid, segment too large
]

test_cidr_ranges_ipv4 = [
    "192.168.1.0/29",       # Valid IPv4 CIDR
    "192.168.1.0/30",       # Small range
    "192.168.1.0/24",       # Larger valid range
    "10.0.0.0/8",           # Single octet large range
    "172.16.0.0/12",        # Private IP range
    "2001:db8::/120",       # Invalid (IPv6)
    "invalid_cidr",         # Invalid input
    "192.168.1.0/33",       # Invalid CIDR mask
    "192.168.1.0/32",       # Single host range
    "192.168.1.10-192.168.1.20",  # Non-CIDR range
]

test_cidr_ranges_ipv6 = [
    "2001:db8::/126",   # Small range (4 IPs)
    "2001:db8::/120",   # Manageable range (256 IPs)
    "2001:db8::/64",    # Too large to expand
]

# Utility to print test results
def print_test_results(valid, invalid, title):
    print(f"\n{title} - Valid:")
    for ip in valid:
        print(f"  - {ip}")
    print(f"\n{title} - Invalid:")
    for ip, error in invalid:
        print(f"  - {ip}: {error}")

