#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import jinja2
from ipaddress import ip_network, ip_address
from json import JSONDecoder
from collections import OrderedDict


# Custom Jinja2 filters
def deepest_node(d, ret={}):
    """Retrieve the lowest level nodes in a nested dictionary"""
    for k in d.keys():
        if isinstance(d[k], dict):
            deepest_node(d[k])
        else:
            ret[k] = d[k]
    return ret


def retrieve_groups(d, ret={}):
    """Retrieve all keys and their first successor(s)"""
    ret.update({k: [sub_k for sub_k in v] for k, v in d.items() if isinstance(v, dict)})
    for v in d.values():
        if not isinstance(v, dict):
            continue
        retrieve_groups(d=v, ret=ret)
    return ret


def mask_to_cidr(netmask):
    """Convert netmask in dot-notation to decimal CIDR notation"""
    return sum(bin(int(x)).count('1') for x in netmask.split('.'))


def flatten(nested_list):
    """Convert a list with arbitrary levels of nesting to a single-level list"""
    return [nested_list] if not isinstance(nested_list, list) else [x for X in nested_list for x in flatten(X)]


def check_dns(input_string):
    """Check for alpha characters in string to check for DNS names"""
    return re.match('[a-zA-Z]', input_string)


def check_wildcard(wildcard):
    """Check whether a given dot-notation mask is a wildcard"""
    b_wildcard = format(int(ip_address(wildcard)), 'b')
    return True if len(b_wildcard) != 32 or re.match(r'1.+0.+1', b_wildcard) else False


def check_ip_addr(ip_as_string):
    """Check whether a given string is a valid IP address"""
    try:
        ip_network(ip_as_string)
        return True
    except ValueError:
        return False


def to_range(network_with_mask):
    """Retrieve first and last IP address for a given network"""
    ip_range_start = (ip_network(network_with_mask).network_address)
    ip_range_end = (ip_network(network_with_mask).broadcast_address)
    return ip_range_start, ip_range_end


# Retain policy order when reading in data
custom_decoder = JSONDecoder(object_pairs_hook=OrderedDict)
policy = custom_decoder.decode(open('output/MGT-CLOUD_run_conf.json').read())

# Set up Jinja2 environment
loader = jinja2.FileSystemLoader(
    searchpath="./templates"
)
env = jinja2.Environment(
    loader=loader,
    extensions=['jinja2.ext.do']
)
env.filters.update({  # Inject custom environment filters
    'deepest_node': deepest_node,
    'retrieve_groups': retrieve_groups,
    'mask_to_cidr': mask_to_cidr,
    'flatten': flatten,
    'check_dns': check_dns,
    'check_wildcard': check_wildcard,
    'check_ip_addr': check_ip_addr,
    'to_range': to_range
})

# Parse template to output
template = env.get_template("fortigate_config.jinja2")
conf_render = template.render(policy=policy)
[print(line.strip()) for line in conf_render.splitlines() if line.strip()]
