import json
import os

import click
import demo_firewall


@click.group()
def cli():
    """CLI tool for managing firewall tasks."""
    pass

@cli.command()
@click.option('--input', required=False, default="paloalto_config.txt", type=click.Path(exists=True), help='Input file for checkpoint config.')
def parse_palo(input):
    """Task to parse Palo Config."""
    click.echo(f"Parsing input file: {input}")
    input_file = open(input, 'r')
    config = input_file.read()
    demo_firewall._get_address_objects(config)
    demo_firewall._get_service_objects(config)
    demo_firewall._get_rule_objects(config)
    

@cli.command()
@click.option('--device', required=False, default="nyc-fw01", type=str, help='Device name.')
def publish(device):
    """Root task of publish data."""
    firewall_data = demo_firewall._get_checkpoint_json()
    demo_firewall.nb.publish_data(firewall_data, device)

    
@cli.command()
@click.option('--device', required=False, default="nyc-fw01", type=str, help='Device name.')
def generate_config(device):
    """Root task of publish data."""
    demo_firewall.nb.generate_config(device)

@cli.command()
def parse_checkpoint():
    """Root task of getconfig."""
    firewall_data = demo_firewall._get_checkpoint_json()

    # # Replace domainId with nice_name in source and destination
    # for rule in rulebase_data.get('rulebase', []):
    #     if 'source' in rule:
    #         original_value = rule.get("source", {})
    #         for source in rule['source']:
    #             if isinstance(source, dict):
    #                 original_value = source.get('domainId', {}).get('nice_name')
    #             source['domainId']["uid"] = hosts_to_nice_name.get(original_value, original_value)


    #     if 'destination' in rule:
    #         original_value = rule.get("destination", {})
    #         for destination in rule['destination']:
    #             if isinstance(destination, dict):
    #                 original_value = destination.get('domainId', {}).get('nice_name')
    #             destination['domainId']["uid"] = hosts_to_nice_name.get(original_value, original_value)


    #     if 'service' in rule:
    #         original_value = rule.get("service", {})
    #         for service in rule['service']:
    #             if isinstance(service, dict):
    #                 original_value = service.get('domainId', {}).get('nice_name')
    #             service['domainId']["uid"] = services_to_nice_name.get(original_value, original_value)

    # # Output the modified rulebase data
    click.echo("Direwall_data data:")
    click.echo(json.dumps(firewall_data, indent=4))

if __name__ == '__main__':
    cli()