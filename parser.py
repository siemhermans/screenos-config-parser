#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import json
from itertools import chain
from collections import defaultdict, OrderedDict
from netaddr import IPAddress


def recursive_resolve(groups, objects):
    group_dicts = {k: {} for k in groups}
    for g in group_dicts:
        for child_key in groups[g]:
            child = group_dicts.get(child_key, objects.get(child_key))
            group_dicts[g][child_key] = child
    not_top_levels = set(chain.from_iterable(groups.values()))  # Remove previously seen entries
    result = {g: group_dicts[g] for g in group_dicts if g not in not_top_levels}
    return result


def recursive_lookup(k, d):
    """
    Find key recursively in Dict.
    :param k:
    :param d:
    :return:
    """
    if k in d: return d[k]
    for v in d.values():
        if isinstance(v, dict):
            a = recursive_lookup(k, v)
            if a is not None: return a
    return None


def cidr_to_mask(cidr):
  """
  Converts decimal CIDR notation to a quad dotted subnetmask.
  :param cidr: Decimal CIDR number
  :return: Quad dotted subnetmask as string
  """
  cidr = int(cidr)
  mask = (0xffffffff >> (32 - cidr)) << (32 - cidr)
  return (str((0xff000000 & mask) >> 24) + '.' +
          str((0x00ff0000 & mask) >> 16) + '.' +
          str((0x0000ff00 & mask) >> 8) + '.' +
          str((0x000000ff & mask)))


def txt_to_list(file_path):
    """
    Reads each line of a given text file into a list.
    :param file_path: Path to the text file.
    :return: List of lines.
    """
    with open(file_path, 'r') as f:
        txt_lines = [i.strip() for i in f.readlines()]
    return txt_lines


def value_by_index(input_list, base_object, index_offset=0):
    """
    Retrieves the value of a given list item by index. By changing the optional offset, the
    value of a positionally relative list item is retrieved.
    :param input_list: List of objects
    :param base_object: Reference object in input_list
    :param index_offset: Optional index offset
    :return:
    """
    value = input_list[input_list.index(base_object) + index_offset]
    return value


def sos_combine_policy_rules(data):
    """  # TODO: Fix description
    Combines separate ScreenOS policy rules into a list based on the unique policy identifier.
    :param data:
    :return:
    """
    include_line = False
    policy_set, unique_policy = ([] for i in range(2))

    for line in data:
        line = line.rstrip('\n')
        # Grab everything from 'set policy id' to 'exit'
        if 'set policy id' in line:
            include_line = True
        elif 'exit' in line:
            include_line = False

        if include_line:
            unique_policy.append(line)
        elif not include_line:
            policy_set.append(unique_policy)
            unique_policy = []

    policy_set = [i for i in policy_set if i]  # Remove empty lists created for non-policy lines
    return policy_set


def sos_parse_filter_rules(policy_set, parsed_pol_set=OrderedDict()):
    """
    # TODO: Fix description
    :param policy_set:
    :return:
    """

    # Define Type of Service (TOS) to priority mapping. CS7 = 0, (...), CS0 = 7
    tos_prio_mapping = {i: 'CS' + str(j) for i, j in zip(range(0, 8), reversed(range(0, 8)))}

    for policy in policy_set:
        # (Re)initialize default values
        pol_id, pol_name, src_zone, dst_zone, pol_action, log_action, \
        pol_qos, sess_lim, sess_amount, pol_app = ('',) * 10
        src_addr, dst_addr, pol_proto = ([] for i in range(3))
        pol_state = 'enabled'

        for row in policy:
            _split, quote_split = row.split(), row.split('"')

            # Handle primary policy rule
            var_index = 0
            if 'policy id' in row and 'from' in row:
                if 'name' in row:
                    pol_name = quote_split[1]
                    var_index += 2
                pol_id = row.split()[3]  # Retrieve policy id
                src_zone, dst_zone = quote_split[var_index + 1], quote_split[var_index + 3]  # Retrieve zones
                src_addr.append(quote_split[var_index + 5]), dst_addr.append(
                    quote_split[var_index + 7])  # Get 'src' and 'dst' from first line
                pol_proto.append(quote_split[var_index + 9])  # Get service proto from first line
                if ' log' in row: log_action = 'log'  # Retrieve log action

                # Retrieve Type of Service prio mapping (lower is more preferred)
                if 'priority' in row:
                    tos_prio = int(value_by_index(_split, 'priority', 1))
                    pol_qos = tos_prio_mapping[tos_prio]

                # Retrieve policy action
                pol_action = re.findall('deny|permit|reject|tunnel', row)[0]

            # Handle secondary policy rule(s)
            if 'application' in quote_split[0]:
                pol_app = quote_split[1]
            if 'disable' in row:  # Get rule state
                pol_state = 'disabled'
            if 'src-address' in row:
                src_addr.append(quote_split[1])
            if 'dst-address' in row:
                dst = quote_split[1]
                # TODO: Handle MIP/VIP addr rewrite in final output. Currently MIP/VIP has no resolved dst_ip
                # if 'MIP(' in dst or 'VIP(' in dst:
                #     dst = ''.join(re.findall(r'\d.+\d', dst))
                dst_addr.append(dst)
            if 'set service' in row:
                pol_proto.append(quote_split[1])
            if 'sess-limit' in row:
                sess_lim = value_by_index(_split, 'sess-limit', 1)
                sess_amount = value_by_index(_split, 'sess-limit', 2)

        parsed_pol_set[pol_id] = {  # OrderedDict() because the order of policies matters.
            'pol_name': pol_name,
            'pol_state': pol_state,
            'src_zone': src_zone,
            'dst_zone': dst_zone,
            'src_addr': list(set(src_addr)),
            'dst_addr': list(set(dst_addr)),
            'pol_proto': list(set(pol_proto)),
            'pol_app': pol_app,
            'pol_action': pol_action,
            'log_action': log_action,
            'pol_qos': pol_qos,
            'sess_lim': sess_lim,
            'sess_amount': sess_amount
        }
    return parsed_pol_set


def sos_parse_nat_rules(policy_set, config_lines):
    """
    # TODO: Fix description
    # TODO: Destination range NAT
    :param policy_set:
    :param config_lines:
    :return:
    """
    parsed_nat_rules = {}

    for policy in policy_set:
        nat_operation, nat_dip_group, nat_src_range_start, nat_src_range_end, \
        nat_dst_ip, nat_dst_port, nat_mip_vrouter = ('',) * 7

        for row in policy:
            words = row.split()

            # Retrieve policy ID
            if re.search(r'\bid\b', row):
                pol_id = value_by_index(words, 'id', 1)

            if re.search(r'\bnat\b', row):
                # Handle NAT rules for tunnels
                if re.search('nat src dst', row):
                    nat_operation = 'Tunnel_MIP'
                    if value_by_index(words, 'nat', 3):
                        nat_dst_ip = value_by_index(words, 'nat', 4) + '/255.255.255.255'

                # Handle combined SNAT and DNAT
                elif re.search('nat src .* dst', row):
                    nat_operation = 'SNAT/DNAT'
                    nat_dst_ip = value_by_index(words, 'ip', + 1) + '/255.255.255.255'

                # Handle SNAT or DNAT scenario
                else:
                    nat_operation = value_by_index(words, 'nat', 1)[0].upper() + 'NAT'
                    if value_by_index(words, 'nat', 1) == 'dst' and 'ip' in row:
                        nat_dst_ip = value_by_index(words, 'dst', 2) + '/255.255.255.255'

                # Convert DIP-group ID to CIDR range
                if 'dip-id' in row:
                    nat_dip_group = value_by_index(words, 'dip-id', 1)

                    for line in config_lines:
                        if 'dip ' + nat_dip_group in line:
                            var_index = line.split().index('dip')
                            nat_src_range_start = line.split()[var_index + 2]
                            nat_src_range_end = line.split()[var_index + 3]

                # Handle DNAT ports
                if re.search(r'\bport\b', row):
                    nat_dst_port = value_by_index(words, 'port', 1)

            # Handle virtual IPs
            if re.search('VIP(.*)', row):
                nat_operation = 'DNAT_VIP'
                nat_vip_ip = re.findall('(?<=VIP\().*?(?=\))', row)
                nat_vip_srv_ip, nat_vip_virt_port, nat_dst_port = ([] for i in range(3))

                for line in config_lines:
                    if nat_vip_ip[0] in line and 'interface' in line:
                        nat_dst_ip = value_by_index(line.split(), 'vip', 1)
                        nat_vip_srv_ip.append(line.split('"')[2].split()[0].strip())
                        if ' + ' in line:
                            nat_dst_port.append(value_by_index(line.split(), nat_dst_ip, 2))
                        else:
                            nat_dst_port.append(value_by_index(line.split(), nat_dst_ip, 1))
                # Rewrite destination IP
                nat_dst_ip = nat_vip_srv_ip


            # Handle mapped IP entries
            if re.search('MIP(.*)', row):
                nat_operation = 'DNAT_MIP'
                nat_mip_ip = re.findall('(?<=MIP\().*?(?=\))', row)

                for line in config_lines:
                    if nat_mip_ip[0] in line and 'interface' in line:
                        nat_dst_ip = value_by_index(line.split(), 'host', 1)
                        nat_dst_ip_mask = value_by_index(line.split(), 'host', 3)
                        nat_dst_ip = [nat_dst_ip + '/' + str(IPAddress(nat_dst_ip_mask).netmask_bits())]  # TODO: Convert to std. lib 'ipaddress'
                        nat_mip_vrouter = value_by_index(line.split(), 'vr', 1).strip('"')

            # TODO: Map correct Server:Port combination to policy rule for VIPs
            parsed_nat_rules[pol_id] = {
                'nat_operation': nat_operation,
                'nat_dip_group': nat_dip_group,
                'nat_src_range_start': nat_src_range_start,
                'nat_src_range_end': nat_src_range_end,
                'nat_dst_ip': nat_dst_ip,
                'nat_dst_port': nat_dst_port,
                'nat_mip_vrouter': nat_mip_vrouter
            }
    return parsed_nat_rules


def sos_parse_addr_objects(config_lines):
    """
    # TODO: Fix description
    :param config_lines:
    :return:
    """
    addr_objects, addr_groups = ({} for i in range(2))

    for line in config_lines:
        # Handle address objects
        if 'address' in line and line.split('"')[0].split()[1] == 'address':
            addr_name = line.split('"')[3]
            addr_content = line.split('"')[4].strip()
            if ' ' in addr_content:
                addr_content = addr_content.replace(' ', '/')
            addr_objects[addr_name] = [addr_content]

        # Handle address groups
        if line.split('"')[0].strip() == 'set group address':
            addr_group_name = line.split('"')[3]
            if not addr_group_name in addr_groups:
                addr_groups[addr_group_name] = []
            if line.split('"')[4].strip() == 'add':
                addr_groups[addr_group_name].append(line.split('"')[5])

    return addr_objects, addr_groups


def sos_parse_def_srv_objects(predef_srv_obj_lines, predef_srv_group_lines):
    """
    # TODO: Fix description
    :param predef_srv_obj_lines:
    :param predef_srv_group_lines:
    :return:
    """
    def_srv_objects, def_srv_groups = ({} for i in range(2))

    # Handle default service objects
    for line in predef_srv_obj_lines:
        if len(re.split(r'\s{2,}', line)) == 5:
            predef_srv = re.split(r'\s{2,}', line)
            predef_srv[2] = re.split(r'\s{2,}', line)[2].split(' ', 1)

            srv_name = predef_srv[0]
            if r'/' in predef_srv[2][0]:
                srv_proto = predef_srv[2][0].replace('/', '-')
            else:
                srv_proto = predef_srv[2][0] + '-' + predef_srv[2][0]

            if predef_srv[1] == '17':
                srv_proto = 'udp_src_0-65535_dst_' + srv_proto
            elif predef_srv[1] == '6':
                srv_proto = 'tcp_src_0-65535_dst_' + srv_proto
            elif predef_srv[1] == '0':
                srv_proto = 'any'
            elif predef_srv[1] == 'RPC':
                srv_proto = 'RPC'
            else:
                srv_proto = 'ip-' + str(predef_srv[1])

            def_srv_objects[srv_name] = [srv_proto]

    # Handle default service groups
    for line in predef_srv_group_lines:
        if 'group' in line:
            def_srv_group_name = value_by_index(line.split(), 'group', 1)
            def_srv_groups[def_srv_group_name] = []
        if 'Members:' in line:
            group_members = re.findall(r'"(.*?)"', line)
            def_srv_groups[def_srv_group_name] = group_members
    return def_srv_objects, def_srv_groups


def sos_parse_srv_objects(config_lines):
    """
    # TODO: Fix description
    :param config_lines:
    :return:
    """
    srv_objects = defaultdict(list)
    srv_groups = {}

    for line in config_lines:
        # Handle service objects
        if re.search('service.*port\s\d{1,5}-\d{1,5}', line):
            srv_name = line.split('"')[1]
            srv_definition = line.split('"')[2].split()

            # Handle protocols
            if srv_definition[1].isdigit():  # Handle non-TCP/UDP protocols
                srv_proto = 'ip-' + str(srv_definition[1])
            else:
                srv_proto = srv_definition[1] + '_src_' + srv_definition[3] + '_dst_' + srv_definition[5]
            srv_objects[srv_name].append(srv_proto)

            # Handle timeouts  # TODO: Currently not returned
            if any("timeout" in i for i in srv_definition):
                srv_timeout = value_by_index(srv_definition, 'timeout', 1) + 's'

        # Handle service groups
        if line.split('"')[0].strip() == 'set group service':
            srv_group_name = line.split('"')[1]
            if not srv_group_name in srv_groups:
                srv_groups[srv_group_name] = []
            # # TODO: Handle srv group comments
            # if line.split('"')[2].strip() == 'comment':
            #     srv_group_comment = line.split('"')[3]
            if line.split('"')[2].strip() == 'add':
                srv_groups[srv_group_name].append(line.split('"')[3])

    return srv_objects, srv_groups


if __name__ == '__main__':
    # Read in raw config / output files
    config_in_file_path = 'input/MGT-CLOUD_run_conf.txt'
    def_srv_obj_lines = txt_to_list('input/sos_predef_srv_objects.txt')
    def_srv_group_lines = txt_to_list('input/sos_predef_srv_groups.txt')
    config_out_file_path = 'output/MGT-CLOUD_run_conf.json'
    config_lines = txt_to_list(config_in_file_path)

    # Extract address objects
    addr_objects, addr_groups = sos_parse_addr_objects(config_lines)
    resolved_addr_groups = recursive_resolve(addr_groups, addr_objects)  # Resolve nested groups
    [resolved_addr_groups.update({k:v}) for k, v in addr_objects.items() if k not in resolved_addr_groups]

    # Extract user and default service objects
    def_srv_objects, def_srv_groups = sos_parse_def_srv_objects(def_srv_obj_lines, def_srv_group_lines)
    srv_objects, srv_groups = sos_parse_srv_objects(config_lines)

    # Merge default and user defined sets
    srv_objects, srv_groups = {**srv_objects, **def_srv_objects}, {**srv_groups, **def_srv_groups}

    # Resolve nested service groups
    resolved_srv_objects = recursive_resolve(srv_groups, srv_objects)
    [resolved_srv_objects.update({k: v}) for k, v in srv_objects.items() if k not in resolved_srv_objects]

    # Combine firewall policies based on policy ID (Removing newlines)
    combined_pol_set = sos_combine_policy_rules(config_lines)
    parsed_filter_rules = sos_parse_filter_rules(combined_pol_set)  # Parse filter rules
    parsed_nat_rules = sos_parse_nat_rules(combined_pol_set, config_lines)  # Parse NAT rules
    [parsed_filter_rules[key].update(parsed_nat_rules[key]) for key in parsed_filter_rules]  # Merge the dicts

    # Replace objects inline
    for rule in parsed_filter_rules:
        resolved_service = {}
        for proto in parsed_filter_rules[rule]['pol_proto']:
            resolved_service.update({proto: resolved_srv_objects[proto]})
        parsed_filter_rules[rule]['pol_proto'] = resolved_service

        resolved_src_addr = {}
        for addr in parsed_filter_rules[rule]['src_addr']:
            resolved_src_addr.update({addr: recursive_lookup(addr, resolved_addr_groups)})
        parsed_filter_rules[rule]['src_addr'] = resolved_src_addr

        resolved_dst_addr = {}
        for addr in parsed_filter_rules[rule]['dst_addr']:
            resolved_dst_addr.update({addr: recursive_lookup(addr, resolved_addr_groups)})
        parsed_filter_rules[rule]['dst_addr'] = resolved_dst_addr

    # Output config file to JSON
    with open('output/MGT-CLOUD_run_conf.json', "w") as f:
        json.dump(parsed_filter_rules, f)
