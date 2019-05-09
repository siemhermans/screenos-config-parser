# ScreenOS Configuration Parser (WIP)
This repository provides a script for extracting filter and NAT rules from a ScreenOS configuration and subsequently converting them to JSON. Additionally, address objects, address groups, service objects and service groups are extracted. 

The parser is a work in progress and does not provide a full ScreenOS syntax. Obscure configurations may fail to be represented correctly.

## Example

Given the following ScreenOS policy, with referenced objects:

```aconf
# Firewall policy
set policy id 10 name "Example Policy" from "TRUST" to "UNTRUST" "Internal Group 1" "External Location" "HTTP" nat src dip-id 7 permit log traffic priority 0 sess-limit per-src-ip 10
set policy id 10 application "HTTP"
set policy id 10
set src-address "Internal Group 2"
set service "HTTP"
set service "HTTPS"
set log session-init
exit

# Address objects
set address "TRUST" "Element 1" 10.0.1.0 255.255.255.0
set address "TRUST" "Element 2" 10.0.2.0 255.255.255.0
set address "TRUST" "Subelement 1" 10.0.3.0 255.255.255.0
set address "UNTRUST" "External Location" 71.24.123.2 255.255.255.255

# Address groups
set group address "TRUST" "Internal Group 1" add "Element 1"
set group address "TRUST" "Internal Group 2" add "Element 2" "Subgroup 1"
set group address "TRUST" "Subgroup 1" add "Subelement 1"

# NAT DIP Group
set interface ethernet0/0 dip 7 65.222.55.7 65.222.55.9
```

Parsing the policy results in the following JSON object:

```javascript
{
  "10": {
    "pol_name": "Example Policy",
    "pol_state": "enabled",
    "src_zone": "TRUST",
    "dst_zone": "UNTRUST",
    "src_addr": {
      "Internal Group 1": {
        "Element 1": [
          "10.0.1.0/255.255.255.0"
        ]
      },
      "Internal Group 2": {
        "Element 2": [
          "10.0.2.0/255.255.255.0"
        ],
        "Subgroup 1": {
          "Subelement 1": [
            "10.0.3.0/255.255.255.0"
          ]
        }
      }
    },
    "dst_addr": {
      "External Location": [
        "71.24.123.2/255.255.255.255"
      ]
    },
    "pol_proto": {
      "HTTP": [
        "tcp_src_0-65535_dst_80-80"
      ],
      "HTTPS": [
        "tcp_src_0-65535_dst_443-443"
      ]
    },
    "pol_app": "HTTP",
    "pol_action": "permit",
    "log_action": "log",
    "pol_qos": "CS7",
    "sess_lim": "per-src-ip",
    "sess_amount": "10",
    "nat_operation": "SNAT",
    "nat_dip_group": "7",
    "nat_src_range_start": "65.222.55.7",
    "nat_src_range_end": "65.222.55.9",
    "nat_dst_ip": "",
    "nat_dst_port": "",
    "nat_mip_vrouter": ""
  },
}
```

The `parser` script takes a full ScreenOS (running) configuration and extracts all objects referenced in the defined firewall policies. 
