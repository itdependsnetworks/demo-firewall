import pynautobot
import os

NAUTOBOT_URL = os.getenv("NAUTOBOT_URL", "https://demo.nautobot.com:8080")
NAUTOBOT_TOKEN = os.getenv("NAUTOBOT_TOKEN", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")

def publish_data(firewall_data, device):
    nb = pynautobot.api(url=NAUTOBOT_URL, token=NAUTOBOT_TOKEN)

    # Access firewall models plugin endpoints
    ip_addresses = nb.ipam.ip_addresses
    address_objects = nb.plugins.firewall.address_object
    service_objects = nb.plugins.firewall.service_object
    policy_rules = nb.plugins.firewall.policy_rule
    policies = nb.plugins.firewall.policy
    policy_to_device = nb.plugins.firewall.policy_device_association
    devices = nb.dcim.devices
    locations = nb.dcim.locations

    # Helper function for idempotent creation
    def get_or_create(endpoint, key, data, lookup_field="name"):
        """Get an object by lookup_field or create it if it doesn’t exist."""
        obj = endpoint.get(**{lookup_field: data[lookup_field]})
        if not obj:
            print(f"Creating {lookup_field}: {data[lookup_field]}")
            obj = endpoint.create(**data)
        else:
            print(f"Found existing {lookup_field}: {data[lookup_field]}")
        return obj

    # Create IP Address Objects Idempotently
    ip_address_map = {}
    for desc, ips in firewall_data["address_objects"].items():
        for ip in ips:
            ip_data = {
                "address": ip + "/32",
                "dns_name": desc,
                "status": "Active",
                "namespace": "Global",
            }
            ip_obj = get_or_create(ip_addresses, "address", ip_data, lookup_field="dns_name")
            ip_address_map[desc] = ip_obj

    # Create Firewall Address Objects Idempotently
    address_object_map = {}
    for desc, ips in firewall_data["address_objects"].items():
        addr_data = {
            "name": desc,
            "ip_address": str(ip_address_map[desc].id)
        }
        addr_obj = get_or_create(address_objects, "name", addr_data)
        address_object_map[desc] = addr_obj

    # Create Service Objects Idempotently
    service_object_map = {}
    for name, services in firewall_data["service_objects"].items():
        for svc in services:
            svc_data = {
                "name": name,
                "ip_protocol": svc["protocol"].upper(),
                "port": svc["port"],
            }
            svc_obj = get_or_create(service_objects, "name", svc_data)
            service_object_map[name] = svc_obj

    # Create Device nyc-fw01 Idempotently
    location = get_or_create(locations, "name", {"name": "NYC01", "status": "Active"}, lookup_field="name")
    device_data = {
        "name": device,
        "device_type": {"model": "PA-3020"},
        "platform": {"name": "Palo Alto"},
        "role": "WAN",
        "status": "Active",  # Using slug
        "location": str(location.id)
    }
    device = get_or_create(devices, "name", device_data)

    # Create Rules Idempotently and Collect Rule IDs
    rule_ids = []
    for rule_name, rule_data in firewall_data["rules"].items():
        src = rule_data["source"]
        dst = rule_data["destination"]

        rule_data_full = {}
        
        # Handle 'any' and list cases
        if src == ["Any"]:
            pass
        elif isinstance(src, list):
            src_addrs = [str(address_object_map[s].id) if s in address_object_map else {"ip_addresses": [{"address": s + "/32"}]} for s in src]
            rule_data_full["source_addresses"] = src_addrs
        else:
            src_addrs = [str(address_object_map[src].id)]
            rule_data_full["source_addresses"] = src_addrs

        if dst == ["Any"]:
            pass
        elif isinstance(dst, list):
            dst_addrs = [str(address_object_map[d].id) if d in address_object_map else {"ip_addresses": [{"address": d + "/32"}]} for d in dst]
            rule_data_full["destination_addresses"] = dst_addrs
        else:
            dst_addrs = [str(address_object_map[dst].id)]
            rule_data_full["destination_addresses"] = dst_addrs

        # Handle services
        svc = rule_data["service"]
        if svc == ["application-default"]:
            pass
        elif isinstance(svc, list):
            services = [str(service_object_map[s].id) if s in service_object_map else s for s in svc]
            rule_data_full["destination_services"] = services
        else:
            services = [str(service_object_map[svc].id)]
            rule_data_full["destination_services"] = services
        
        rule_data_full["name"] = rule_name
        rule_data_full["action"] = "allow"
        rule_data_full["source_zone"] = "LAN"
        rule_data_full["destination_zone"] = "WAN"
        
        rule = get_or_create(policy_rules, "name", rule_data_full)
        rule_ids.append(str(rule.id))

    # Create Policy nyc-fw-policy Idempotently and Apply Rules
    policy_data = {
        "name": "nyc-fw-policy",
        "policy_rules": rule_ids,
    }
    policy = get_or_create(policies, "name", policy_data)
    # print(json.dumps(dict(policy), indent=4))

    policy_to_device_data = {
        "policy": str(policy.id),
        "device": str(device.id),
    }
    policy_to_device = get_or_create(policy_to_device, "policy", policy_to_device_data, lookup_field="policy")

    print("Firewall configuration and policy assignment completed.")

def generate_config(device):
    nb = pynautobot.api(url=NAUTOBOT_URL, token=NAUTOBOT_TOKEN)
    devices = nb.dcim.devices
    capirca_policies = nb.plugins.firewall.capirca_policy

    device = devices.get(**{"name": device})

    job = nb.extras.jobs.get(**{"module_name": "nautobot_firewall_models.jobs", "job_class_name": "RunCapircaJob"})
      
    job_result = nb.extras.jobs.run(
        job_id=str(job.id),
        data={"device": [str(device.id)]},
        commit=True,
    )

    capirca_policies = nb.plugins.firewall.capirca_policy.get(**{"device": str(device.id)})
    print(f"Palo Config:\n {capirca_policies.cfg}")