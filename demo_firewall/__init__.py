import re
import os
import json


def _get_checkpoint_json():
    hosts_file = "show-hosts.json"
    access_rulebase_file = "show-access-rulebase.json"
    services_file = "show-services.json"
    if not os.path.exists(hosts_file) or not os.path.exists(access_rulebase_file) or not os.path.exists(services_file):
        raise ValueError("Required files (show-hosts.json, show-services.json or show-access-rulebase.json) are missing.")

    with open(hosts_file, 'r') as f:
        hosts_data = json.load(f)

    with open(services_file, 'r') as f:
        services_data = json.load(f)

    with open(access_rulebase_file, 'r') as f:
        rulebase_data = json.load(f)

    data = {
        "hosts": hosts_data,
        "services": services_data,
        "rulebase": rulebase_data
    }
    return convert_checkpoint_json_files(data)


def _get_address_objects(input):
    data = {}

    for line in input.splitlines():
        interesting_line = re.search(r'set address\s+(\S+)\s+ip-netmask\s+(.+)', line)
        if interesting_line:
            name = interesting_line.group(1)
            if not data.get(name):
                data[name] = []
            data[name].append(interesting_line.group(2))
    return data
        
def _get_service_objects(input):
    data = {}

    for line in input.splitlines():
        interesting_line = re.search(r'set service\s+(\S+)\s+protocol\s+(\S+)\s+port\s+(\S+)', line)
        if interesting_line:
            name = interesting_line.group(1)
            if not data.get(name):
                data[name] = []
            data[name].append({
                "protocol": interesting_line.group(2),
                "port": interesting_line.group(3)
            })
    return data


def _get_rule_objects(input):
    data = {}
    for line in input.splitlines():
        interesting_line = re.search(r'set rulebase security rules\s+(\S+)\s+(.+)', line)
        if interesting_line:
            name = interesting_line.group(1)
            if not data.get(name):
                data[name] = {}
            detail_info = re.search(r'(destination|service|source)\s+(.+)', interesting_line.group(2))
            if detail_info:
                if '[' in detail_info.group(2): 
                    objects = re.findall(r'\[(.*?)\]', detail_info.group(2))
                    if objects:
                        objects = objects[0].split()
                        data[name][detail_info.group(1)] = objects
                else:                    
                    data[name][detail_info.group(1)] = detail_info.group(2)
    return data


def parse(input):
    address_objects = _get_address_objects(input)
    service_objects = _get_service_objects(input)
    rules = _get_rule_objects(input)
    return {"address_objects": address_objects, "service_objects": service_objects, "rules": rules}

def convert_checkpoint_json_files(obj):
    converted_data = {
        'address_objects': {},
        'service_objects': {},
        'rules': {}
    }
    host_mapping = {}
    # Process hosts
    if obj.get("hosts", {}).get("objects", []):
        for host in obj["hosts"]["objects"]:
            name = host.get("name")
            ip = host.get("ipv4-address")
            uid = host.get("uid")
            if name and ip:
                converted_data['address_objects'][name] = [ip]
                host_mapping[uid] = name

    service_mapping = {}
    if obj.get("services", {}).get("objects", []):
        for service in obj["services"]["objects"]:
            name = service.get("name")
            port = service.get("port")
            uid = service.get("uid")
            if name and port:
                converted_data['service_objects'][name] = [{'protocol': "tcp", 'port': port}]
                service_mapping[uid] = name

    if obj.get("rulebase", {}).get("rulebase", []):
        for rule in obj["rulebase"]["rulebase"]:
            rule_name = rule.get("name")
            source = []
            for src in rule.get("source"):
                source_uid = src["domainId"]["uid"]
                if source_uid == "Any":
                    source.append(source_uid)
                else:
                    source.append(host_mapping[source_uid])

            destination = []
            for dst in rule.get("destination"):
                destination_uid = dst["domainId"]["uid"]
                if destination_uid == "Any":
                    destination.append(destination_uid)
                else:
                    destination.append(host_mapping[destination_uid])


            service = []
            for svc in rule.get("service"):
                service_uid = svc["domainId"]["uid"]
                if service_uid == "application-default":
                    service.append(service_uid)
                else:
                    service.append(service_mapping[service_uid])

            if rule_name and source and destination and service:
                converted_data['rules'][rule_name] = {
                    'source': source if source != "any" else "any",
                    'destination': destination if destination != "any" else "any",
                    'service': service if service != "any" else "application-default"
                }
    return converted_data