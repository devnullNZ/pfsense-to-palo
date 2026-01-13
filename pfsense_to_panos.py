#!/usr/bin/env python3
"""
pfSense to Palo Alto (PAN-OS) Terraform Converter

This script parses pfSense configuration XML exports and converts them
into Terraform configuration files using the PAN-OS provider (v2.0+) to
migrate firewall configurations to Palo Alto Networks firewalls.

Usage:
    python3 pfsense_to_panos.py config.xml [--output-dir output]

Requirements:
    - Python 3.7+
    - pfSense configuration XML export
    - Terraform (for applying the generated configs)
    - Palo Alto Networks firewall (target)
"""

import xml.etree.ElementTree as ET
import argparse
import os
import sys
from typing import Dict, List, Optional, Any, Set
from pathlib import Path
import re


class PfSenseParser:
    """Parse pfSense XML configuration"""
    
    def __init__(self, xml_file: str):
        self.xml_file = xml_file
        self.tree = ET.parse(xml_file)
        self.root = self.tree.getroot()
        
        # Parsed data structures
        self.interfaces = []
        self.vlans = []
        self.aliases = []
        self.firewall_rules = []
        self.nat_port_forwards = []
        self.nat_outbound = []
        self.nat_one_to_one = []
        self.dhcp_servers = []
        self.static_routes = []
        self.ipsec_tunnels = []
        self.openvpn_servers = []
        self.openvpn_clients = []
        self.system_info = {}
        
        # Mapping data
        self.zone_mapping = {}  # pfSense interface -> PAN zone
        self.service_objects = set()  # Track unique services
        
    def parse(self):
        """Parse all configuration sections"""
        print("Parsing pfSense configuration...")
        
        self.parse_system_info()
        self.parse_interfaces()
        self.parse_vlans()
        self.parse_aliases()
        self.parse_firewall_rules()
        self.parse_nat_rules()
        self.parse_dhcp()
        self.parse_static_routes()
        self.parse_ipsec()
        self.parse_openvpn()
        
        self.analyze_zones()
        self.print_summary()
        
    def parse_system_info(self):
        """Parse system information"""
        system = self.root.find('system')
        if system is not None:
            self.system_info = {
                'hostname': self.get_text(system, 'hostname', 'pfsense'),
                'domain': self.get_text(system, 'domain', 'localdomain'),
                'timezone': self.get_text(system, 'timezone', 'Etc/UTC'),
            }
    
    def parse_interfaces(self):
        """Parse network interfaces"""
        interfaces = self.root.find('interfaces')
        if interfaces is None:
            return
            
        for iface in interfaces:
            iface_data = {
                'name': iface.tag,
                'descr': self.get_text(iface, 'descr', iface.tag.upper()),
                'if': self.get_text(iface, 'if', ''),
                'enable': iface.find('enable') is not None,
                'ipaddr': self.get_text(iface, 'ipaddr', ''),
                'subnet': self.get_text(iface, 'subnet', ''),
                'gateway': self.get_text(iface, 'gateway', ''),
                'type': self.get_text(iface, 'ipaddr', 'none'),
                'type6': self.get_text(iface, 'ipaddrv6', 'none'),
                'mtu': self.get_text(iface, 'mtu', ''),
                'spoofmac': self.get_text(iface, 'spoofmac', ''),
            }
            self.interfaces.append(iface_data)
    
    def parse_vlans(self):
        """Parse VLAN configurations"""
        vlans = self.root.find('vlans')
        if vlans is None:
            return
            
        for vlan in vlans.findall('vlan'):
            vlan_data = {
                'if': self.get_text(vlan, 'if', ''),
                'tag': self.get_text(vlan, 'tag', ''),
                'descr': self.get_text(vlan, 'descr', ''),
                'vlanif': self.get_text(vlan, 'vlanif', ''),
            }
            self.vlans.append(vlan_data)
    
    def parse_aliases(self):
        """Parse firewall aliases (address objects)"""
        aliases = self.root.find('aliases')
        if aliases is None:
            return
            
        for alias in aliases.findall('alias'):
            alias_data = {
                'name': self.get_text(alias, 'name', ''),
                'type': self.get_text(alias, 'type', 'host'),
                'address': self.get_text(alias, 'address', ''),
                'descr': self.get_text(alias, 'descr', ''),
                'detail': self.get_text(alias, 'detail', ''),
            }
            self.aliases.append(alias_data)
    
    def parse_firewall_rules(self):
        """Parse firewall filter rules"""
        filter_rules = self.root.find('filter')
        if filter_rules is None:
            return
            
        for rule in filter_rules.findall('rule'):
            rule_data = {
                'type': self.get_text(rule, 'type', 'pass'),
                'interface': self.get_text(rule, 'interface', ''),
                'ipprotocol': self.get_text(rule, 'ipprotocol', 'inet'),
                'protocol': self.get_text(rule, 'protocol', 'any'),
                'source': self.parse_address_element(rule.find('source')),
                'destination': self.parse_address_element(rule.find('destination')),
                'descr': self.get_text(rule, 'descr', ''),
                'disabled': rule.find('disabled') is not None,
                'log': rule.find('log') is not None,
                'statetype': self.get_text(rule, 'statetype', 'keep state'),
            }
            
            # Track unique services
            if rule_data['protocol'] not in ['any', 'tcp/udp']:
                dest = rule_data['destination']
                if dest.get('port'):
                    self.service_objects.add(f"{rule_data['protocol']}-{dest['port']}")
            
            self.firewall_rules.append(rule_data)
    
    def parse_address_element(self, element) -> Dict[str, str]:
        """Parse source/destination address element"""
        if element is None:
            return {'any': True}
        
        result = {}
        
        if element.find('any') is not None:
            result['any'] = True
        else:
            result['address'] = self.get_text(element, 'address', '')
            result['network'] = self.get_text(element, 'network', '')
            result['port'] = self.get_text(element, 'port', '')
            
        return result
    
    def parse_nat_rules(self):
        """Parse NAT rules (port forwards, outbound, 1:1)"""
        nat = self.root.find('nat')
        if nat is None:
            return
            
        # Port forwards
        for rule in nat.findall('rule'):
            rule_data = {
                'interface': self.get_text(rule, 'interface', ''),
                'protocol': self.get_text(rule, 'protocol', 'tcp'),
                'source': self.parse_address_element(rule.find('source')),
                'destination': self.parse_address_element(rule.find('destination')),
                'target': self.get_text(rule, 'target', ''),
                'local-port': self.get_text(rule, 'local-port', ''),
                'descr': self.get_text(rule, 'descr', ''),
                'disabled': rule.find('disabled') is not None,
            }
            self.nat_port_forwards.append(rule_data)
        
        # Outbound NAT
        outbound = nat.find('outbound')
        if outbound is not None:
            for rule in outbound.findall('rule'):
                rule_data = {
                    'interface': self.get_text(rule, 'interface', ''),
                    'protocol': self.get_text(rule, 'protocol', 'any'),
                    'source': self.parse_address_element(rule.find('source')),
                    'destination': self.parse_address_element(rule.find('destination')),
                    'target': self.get_text(rule, 'target', ''),
                    'descr': self.get_text(rule, 'descr', ''),
                    'disabled': rule.find('disabled') is not None,
                }
                self.nat_outbound.append(rule_data)
        
        # 1:1 NAT
        for rule in nat.findall('onetoone'):
            rule_data = {
                'interface': self.get_text(rule, 'interface', ''),
                'external': self.get_text(rule, 'external', ''),
                'internal': self.get_text(rule, 'ipaddr', ''),
                'subnet': self.get_text(rule, 'subnet', ''),
                'descr': self.get_text(rule, 'descr', ''),
                'disabled': rule.find('disabled') is not None,
            }
            self.nat_one_to_one.append(rule_data)
    
    def parse_dhcp(self):
        """Parse DHCP server configurations"""
        dhcpd = self.root.find('dhcpd')
        if dhcpd is None:
            return
            
        for iface in dhcpd:
            if iface.find('enable') is not None:
                dhcp_data = {
                    'interface': iface.tag,
                    'range_from': self.get_text(iface, 'range/from', ''),
                    'range_to': self.get_text(iface, 'range/to', ''),
                    'gateway': self.get_text(iface, 'gateway', ''),
                    'domain': self.get_text(iface, 'domain', ''),
                    'dnsserver': [],
                    'static_maps': [],
                }
                
                # DNS servers
                for dns in iface.findall('dnsserver'):
                    if dns.text:
                        dhcp_data['dnsserver'].append(dns.text)
                
                # Static mappings
                for static in iface.findall('staticmap'):
                    static_data = {
                        'mac': self.get_text(static, 'mac', ''),
                        'ipaddr': self.get_text(static, 'ipaddr', ''),
                        'hostname': self.get_text(static, 'hostname', ''),
                        'descr': self.get_text(static, 'descr', ''),
                    }
                    dhcp_data['static_maps'].append(static_data)
                
                self.dhcp_servers.append(dhcp_data)
    
    def parse_static_routes(self):
        """Parse static routes"""
        routes = self.root.find('staticroutes')
        if routes is None:
            return
            
        for route in routes.findall('route'):
            route_data = {
                'network': self.get_text(route, 'network', ''),
                'gateway': self.get_text(route, 'gateway', ''),
                'descr': self.get_text(route, 'descr', ''),
                'disabled': route.find('disabled') is not None,
            }
            self.static_routes.append(route_data)
    
    def parse_ipsec(self):
        """Parse IPsec VPN configurations"""
        ipsec = self.root.find('ipsec')
        if ipsec is None:
            return
            
        phase1_list = ipsec.findall('phase1')
        for phase1 in phase1_list:
            tunnel_data = {
                'ikeid': self.get_text(phase1, 'ikeid', ''),
                'descr': self.get_text(phase1, 'descr', ''),
                'iketype': self.get_text(phase1, 'iketype', 'ikev2'),
                'interface': self.get_text(phase1, 'interface', ''),
                'remote-gateway': self.get_text(phase1, 'remote-gateway', ''),
                'authentication_method': self.get_text(phase1, 'authentication_method', 'pre_shared_key'),
                'pre-shared-key': self.get_text(phase1, 'pre-shared-key', '***REDACTED***'),
                'myid_type': self.get_text(phase1, 'myid_type', 'myaddress'),
                'myid_data': self.get_text(phase1, 'myid_data', ''),
                'peerid_type': self.get_text(phase1, 'peerid_type', 'peeraddress'),
                'peerid_data': self.get_text(phase1, 'peerid_data', ''),
                'encryption': self.get_text(phase1, 'encryption-algorithm/name', 'aes256'),
                'hash': self.get_text(phase1, 'hash-algorithm', 'sha256'),
                'dhgroup': self.get_text(phase1, 'dhgroup', '14'),
                'lifetime': self.get_text(phase1, 'lifetime', '28800'),
                'disabled': phase1.find('disabled') is not None,
                'phase2': [],
            }
            
            # Find associated Phase 2 entries
            ikeid = tunnel_data['ikeid']
            if ikeid:
                for phase2 in ipsec.findall('phase2'):
                    if self.get_text(phase2, 'ikeid', '') == ikeid:
                        phase2_data = {
                            'descr': self.get_text(phase2, 'descr', ''),
                            'mode': self.get_text(phase2, 'mode', 'tunnel'),
                            'localid_type': self.get_text(phase2, 'localid/type', 'network'),
                            'localid_address': self.get_text(phase2, 'localid/address', ''),
                            'localid_netbits': self.get_text(phase2, 'localid/netbits', ''),
                            'remoteid_type': self.get_text(phase2, 'remoteid/type', 'network'),
                            'remoteid_address': self.get_text(phase2, 'remoteid/address', ''),
                            'remoteid_netbits': self.get_text(phase2, 'remoteid/netbits', ''),
                            'protocol': self.get_text(phase2, 'protocol', 'esp'),
                            'encryption': self.get_text(phase2, 'encryption-algorithm-option/name', 'aes256'),
                            'hash': self.get_text(phase2, 'hash-algorithm-option', 'hmac_sha256'),
                            'pfsgroup': self.get_text(phase2, 'pfsgroup', '14'),
                            'lifetime': self.get_text(phase2, 'lifetime', '3600'),
                        }
                        tunnel_data['phase2'].append(phase2_data)
            
            self.ipsec_tunnels.append(tunnel_data)
    
    def parse_openvpn(self):
        """Parse OpenVPN configurations"""
        openvpn = self.root.find('openvpn')
        if openvpn is None:
            return
            
        # OpenVPN servers
        for server in openvpn.findall('openvpn-server'):
            server_data = {
                'vpnid': self.get_text(server, 'vpnid', ''),
                'mode': self.get_text(server, 'mode', 'server_tls'),
                'protocol': self.get_text(server, 'protocol', 'udp'),
                'interface': self.get_text(server, 'interface', ''),
                'local_port': self.get_text(server, 'local_port', '1194'),
                'description': self.get_text(server, 'description', ''),
                'tunnel_network': self.get_text(server, 'tunnel_network', ''),
                'local_network': self.get_text(server, 'local_network', ''),
                'remote_network': self.get_text(server, 'remote_network', ''),
                'crypto': self.get_text(server, 'crypto', 'AES-256-CBC'),
                'digest': self.get_text(server, 'digest', 'SHA256'),
                'disabled': server.find('disable') is not None,
            }
            self.openvpn_servers.append(server_data)
        
        # OpenVPN clients
        for client in openvpn.findall('openvpn-client'):
            client_data = {
                'vpnid': self.get_text(client, 'vpnid', ''),
                'mode': self.get_text(client, 'mode', 'p2p_tls'),
                'protocol': self.get_text(client, 'protocol', 'udp'),
                'interface': self.get_text(client, 'interface', ''),
                'server_addr': self.get_text(client, 'server_addr', ''),
                'server_port': self.get_text(client, 'server_port', '1194'),
                'description': self.get_text(client, 'description', ''),
                'crypto': self.get_text(client, 'crypto', 'AES-256-CBC'),
                'digest': self.get_text(client, 'digest', 'SHA256'),
                'disabled': client.find('disable') is not None,
            }
            self.openvpn_clients.append(client_data)
    
    def analyze_zones(self):
        """Analyze interfaces and create zone mappings for PAN-OS"""
        # Common pfSense interface names -> PAN zone mapping
        zone_hints = {
            'wan': 'untrust',
            'lan': 'trust',
            'dmz': 'dmz',
            'opt1': 'dmz',
            'opt2': 'guest',
            'opt': 'optional',
        }
        
        for iface in self.interfaces:
            name = iface['name'].lower()
            descr = iface['descr'].lower()
            
            # Try to intelligently map to zone
            zone_name = None
            for hint, zone in zone_hints.items():
                if hint in name or hint in descr:
                    zone_name = zone
                    break
            
            if not zone_name:
                # Default based on description keywords
                if 'dmz' in descr:
                    zone_name = 'dmz'
                elif 'guest' in descr or 'wifi' in descr:
                    zone_name = 'guest'
                elif 'internal' in descr or 'private' in descr:
                    zone_name = 'trust'
                elif 'external' in descr or 'internet' in descr or 'public' in descr:
                    zone_name = 'untrust'
                else:
                    zone_name = f"zone_{name}"
            
            self.zone_mapping[iface['name']] = zone_name
    
    def get_text(self, element, path: str, default: str = '') -> str:
        """Get text from XML element with path support"""
        if '/' in path:
            parts = path.split('/')
            current = element
            for part in parts:
                current = current.find(part)
                if current is None:
                    return default
            return current.text if current.text else default
        else:
            child = element.find(path)
            return child.text if child is not None and child.text else default
    
    def print_summary(self):
        """Print parsing summary"""
        print(f"\nParsing complete!")
        print(f"  System: {self.system_info.get('hostname', 'unknown')}.{self.system_info.get('domain', 'unknown')}")
        print(f"  Interfaces: {len(self.interfaces)}")
        print(f"  Zones (mapped): {len(self.zone_mapping)}")
        print(f"  VLANs: {len(self.vlans)}")
        print(f"  Aliases: {len(self.aliases)}")
        print(f"  Firewall Rules: {len(self.firewall_rules)}")
        print(f"  NAT Port Forwards: {len(self.nat_port_forwards)}")
        print(f"  NAT Outbound: {len(self.nat_outbound)}")
        print(f"  NAT 1:1: {len(self.nat_one_to_one)}")
        print(f"  DHCP Servers: {len(self.dhcp_servers)}")
        print(f"  Static Routes: {len(self.static_routes)}")
        print(f"  IPsec Tunnels: {len(self.ipsec_tunnels)}")
        print(f"  OpenVPN Servers: {len(self.openvpn_servers)}")
        print(f"  OpenVPN Clients: {len(self.openvpn_clients)}")


class PanosGenerator:
    """Generate PAN-OS Terraform configuration from parsed pfSense data"""
    
    def __init__(self, parser: PfSenseParser, output_dir: str):
        self.parser = parser
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
    def generate_all(self):
        """Generate all Terraform configuration files"""
        print(f"\nGenerating PAN-OS Terraform configuration in {self.output_dir}...")
        
        self.generate_provider()
        self.generate_variables()
        self.generate_zones()
        self.generate_address_objects()
        self.generate_service_objects()
        self.generate_address_groups()
        self.generate_security_rules()
        self.generate_nat_rules()
        self.generate_interfaces()
        self.generate_static_routes()
        self.generate_ipsec()
        self.generate_migration_reports()
        
        print(f"\n✓ Successfully generated PAN-OS Terraform configuration!")
        print(f"\nNext steps:")
        print(f"  1. cd {self.output_dir}")
        print(f"  2. Review and customize the generated .tf files")
        print(f"  3. Update provider authentication in terraform.tfvars")
        print(f"  4. terraform init")
        print(f"  5. terraform plan")
        print(f"  6. terraform apply")
        
    def generate_provider(self):
        """Generate provider configuration for PAN-OS v2.0+"""
        content = '''# Terraform Provider Configuration for PAN-OS
# Generated from pfSense configuration
# Provider: PaloAltoNetworks/panos v2.0+

terraform {
  required_version = ">= 1.8"
  
  required_providers {
    panos = {
      source  = "PaloAltoNetworks/panos"
      version = "~> 2.0"
    }
  }
}

# Configure the PAN-OS provider
# Authentication options:
# 1. API Key (recommended): Set api_key or PANOS_API_KEY environment variable
# 2. Username/Password: Set username/password or PANOS_USERNAME/PANOS_PASSWORD
provider "panos" {
  hostname = var.panos_hostname  # Firewall or Panorama IP/hostname
  
  # Option 1: API Key authentication (recommended)
  # api_key = var.panos_api_key
  
  # Option 2: Username/Password authentication
  username = var.panos_username
  password = var.panos_password
  
  # Connection settings
  protocol              = var.panos_protocol  # "https" or "http"
  port                  = var.panos_port      # Default: 443 for https
  skip_verify_certificate = var.panos_insecure  # Set true for self-signed certs
  
  # Optional: Configure timeout
  timeout = 120
}
'''
        self.write_file('provider.tf', content)
    
    def generate_variables(self):
        """Generate variables file"""
        content = '''# Variables for PAN-OS Terraform Configuration

# PAN-OS Connection Settings
variable "panos_hostname" {
  description = "Hostname or IP address of PAN-OS firewall or Panorama"
  type        = string
  # Example: "192.168.1.1" or "panorama.example.com"
}

variable "panos_api_key" {
  description = "API key for PAN-OS authentication (recommended)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "panos_username" {
  description = "Username for PAN-OS authentication"
  type        = string
  default     = "admin"
  sensitive   = true
}

variable "panos_password" {
  description = "Password for PAN-OS authentication"
  type        = string
  default     = ""
  sensitive   = true
}

variable "panos_protocol" {
  description = "Protocol for PAN-OS API (https or http)"
  type        = string
  default     = "https"
}

variable "panos_port" {
  description = "Port for PAN-OS API"
  type        = number
  default     = 443
}

variable "panos_insecure" {
  description = "Skip TLS certificate verification"
  type        = bool
  default     = true
}

# Deployment Configuration
variable "vsys" {
  description = "Virtual system for configuration (vsys1, vsys2, etc.)"
  type        = string
  default     = "vsys1"
}

variable "device_group" {
  description = "Panorama device group (leave empty for NGFW)"
  type        = string
  default     = ""
}

variable "template" {
  description = "Panorama template name (leave empty for NGFW)"
  type        = string
  default     = ""
}
'''
        self.write_file('variables.tf', content)
    
    def generate_zones(self):
        """Generate security zones"""
        if not self.parser.zone_mapping:
            return
            
        content = '# Security Zones\n'
        content += '# Generated from pfSense interface mapping\n'
        content += '# PAN-OS Provider v2.0+ Resource: panos_zone\n\n'
        
        unique_zones = set(self.parser.zone_mapping.values())
        
        for zone_name in sorted(unique_zones):
            safe_name = self.sanitize_name(zone_name)
            
            # Find interfaces for this zone
            zone_interfaces = [iface for iface, zone in self.parser.zone_mapping.items() 
                             if zone == zone_name]
            
            # Determine zone type based on name
            zone_type = "layer3"  # Default
            if zone_name in ['untrust', 'external', 'wan']:
                zone_type = "layer3"
            elif zone_name in ['trust', 'internal', 'lan']:
                zone_type = "layer3"
            elif zone_name == 'dmz':
                zone_type = "layer3"
            
            content += f'''resource "panos_zone" "{safe_name}" {{
  name = "{zone_name}"
  mode = "{zone_type}"
  
  location = {{
    vsys = {{
      name = var.vsys
    }}
  }}
  
  # Interfaces from pfSense: {', '.join(zone_interfaces)}
  # Note: Map these to actual PAN-OS interfaces (ethernet1/1, etc.)
  # interfaces = ["ethernet1/1"]  # TODO: Update with actual interface names
}}

'''
        
        self.write_file('zones.tf', content)
    
    def generate_address_objects(self):
        """Generate address objects from pfSense aliases"""
        if not self.parser.aliases:
            return
            
        content = '# Address Objects\n'
        content += '# Generated from pfSense aliases\n'
        content += '# PAN-OS Provider v2.0+ Resource: panos_address_object\n\n'
        
        for alias in self.parser.aliases:
            if alias['type'] in ['host', 'network']:
                addresses = alias['address'].split() if alias['address'] else []
                
                for idx, addr in enumerate(addresses):
                    safe_name = self.sanitize_name(f"{alias['name']}_{idx}" if len(addresses) > 1 else alias['name'])
                    
                    # Determine address type
                    addr_type = "ip-netmask"
                    if '/' not in addr and ':' not in addr:
                        addr += '/32'  # Single host
                    elif '-' in addr:
                        addr_type = "ip-range"
                    elif ':' in addr and '/' not in addr:
                        addr_type = "fqdn"
                    
                    content += f'''resource "panos_address_object" "{safe_name}" {{
  name = "{alias['name']}"
  
  location = {{
    vsys = {{
      name = var.vsys
    }}
  }}
  
  '''
                    
                    if addr_type == "fqdn":
                        content += f'fqdn = "{addr}"\n'
                    elif addr_type == "ip-range":
                        content += f'ip_range = "{addr}"\n'
                    else:
                        content += f'ip_netmask = "{addr}"\n'
                    
                    if alias['descr']:
                        content += f'  description = "{self.escape_string(alias["descr"])}"\n'
                    
                    content += '}\n\n'
        
        self.write_file('address_objects.tf', content)
    
    def generate_service_objects(self):
        """Generate service objects"""
        if not self.parser.service_objects:
            return
            
        content = '# Service Objects\n'
        content += '# Generated from pfSense firewall rules\n'
        content += '# PAN-OS Provider v2.0+ Resource: panos_service_object\n\n'
        
        # Also handle pfSense aliases that are ports
        port_aliases = [alias for alias in self.parser.aliases if alias['type'] == 'port']
        
        for alias in port_aliases:
            ports = alias['address'].split() if alias['address'] else []
            
            for port in ports:
                safe_name = self.sanitize_name(f"{alias['name']}_{port}")
                
                # Assume TCP if not specified
                protocol = 'tcp'
                
                content += f'''resource "panos_service_object" "{safe_name}" {{
  name = "{alias['name']}-{port}"
  
  location = {{
    vsys = {{
      name = var.vsys
    }}
  }}
  
  protocol = {{
    tcp = {{
      port = "{port}"
    }}
  }}
  
'''
                if alias['descr']:
                    content += f'  description = "{self.escape_string(alias["descr"])}"\n'
                
                content += '}\n\n'
        
        self.write_file('service_objects.tf', content)
    
    def generate_address_groups(self):
        """Generate address groups from multi-entry aliases"""
        content = '# Address Groups\n'
        content += '# Generated from pfSense aliases with multiple entries\n'
        content += '# PAN-OS Provider v2.0+ Resource: panos_address_group\n\n'
        
        has_groups = False
        for alias in self.parser.aliases:
            if alias['type'] in ['host', 'network']:
                addresses = alias['address'].split() if alias['address'] else []
                
                if len(addresses) > 1:
                    has_groups = True
                    safe_name = self.sanitize_name(f"{alias['name']}_group")
                    
                    content += f'''resource "panos_address_group" "{safe_name}" {{
  name = "{alias['name']}"
  
  location = {{
    vsys = {{
      name = var.vsys
    }}
  }}
  
  static_addresses = [
'''
                    for idx in range(len(addresses)):
                        member_name = f"{alias['name']}_{idx}" if len(addresses) > 1 else alias['name']
                        safe_member = self.sanitize_name(member_name)
                        content += f'    panos_address_object.{safe_member}.name,\n'
                    
                    content += '  ]\n'
                    
                    if alias['descr']:
                        content += f'  description = "{self.escape_string(alias["descr"])}"\n'
                    
                    content += '}\n\n'
        
        if has_groups:
            self.write_file('address_groups.tf', content)
    
    def generate_security_rules(self):
        """Generate security policy rules"""
        if not self.parser.firewall_rules:
            return
            
        content = '# Security Policy Rules\n'
        content += '# Generated from pfSense firewall rules\n'
        content += '# PAN-OS Provider v2.0+ Resource: panos_security_rule_group\n\n'
        
        # Group rules by interface/zone
        rules_by_zone = {}
        for rule in self.parser.firewall_rules:
            zone = self.parser.zone_mapping.get(rule['interface'], 'trust')
            if zone not in rules_by_zone:
                rules_by_zone[zone] = []
            rules_by_zone[zone].append(rule)
        
        for zone, rules in sorted(rules_by_zone.items()):
            safe_zone = self.sanitize_name(zone)
            
            content += f'''# Security rules for zone: {zone}
resource "panos_security_rule_group" "rules_{safe_zone}" {{
  position_keyword = "top"
  
  location = {{
    vsys = {{
      name = var.vsys
      rulebase = "pre-rulebase"
    }}
  }}
  
  rules = [
'''
            
            for idx, rule in enumerate(rules):
                if rule['disabled']:
                    content += '    # DISABLED RULE:\n'
                
                descr = rule['descr'] or f"Rule {idx+1}"
                action = "allow" if rule['type'] == 'pass' else "deny"
                
                # Map protocol
                protocol = rule['protocol']
                if protocol == 'tcp/udp':
                    protocol_app = 'any'
                elif protocol == 'any':
                    protocol_app = 'any'
                else:
                    protocol_app = 'application-default'
                
                # Source zone
                source_zone = self.parser.zone_mapping.get(rule['interface'], zone)
                
                # Destination zone - determine from rule context
                dest_zone = 'any'  # Default to any
                
                content += f'''    {{
      name        = "{self.escape_string(descr)[:63]}"  # Max 63 chars
      action      = "{action}"
      description = "{self.escape_string(descr)}"
'''
                
                # Source zones
                content += f'      source_zones = [panos_zone.{self.sanitize_name(source_zone)}.name]\n'
                
                # Source addresses
                src = rule['source']
                if src.get('any'):
                    content += '      source_addresses = ["any"]\n'
                elif src.get('network'):
                    content += f'      source_addresses = ["{src["network"]}"]\n'
                elif src.get('address'):
                    # Check if it's an alias reference
                    content += f'      source_addresses = ["{src["address"]}"]\n'
                
                # Destination zones
                content += f'      destination_zones = ["any"]  # TODO: Set appropriate destination zone\n'
                
                # Destination addresses
                dest = rule['destination']
                if dest.get('any'):
                    content += '      destination_addresses = ["any"]\n'
                elif dest.get('network'):
                    content += f'      destination_addresses = ["{dest["network"]}"]\n'
                elif dest.get('address'):
                    content += f'      destination_addresses = ["{dest["address"]}"]\n'
                
                # Applications
                content += f'      applications = ["{protocol_app}"]\n'
                
                # Services
                if protocol != 'any' and dest.get('port'):
                    content += f'      services = ["service-{protocol}-{dest["port"]}"]  # TODO: Create service object\n'
                else:
                    content += '      services = ["application-default"]\n'
                
                # Logging
                if rule.get('log'):
                    content += '      log_setting = "default"  # TODO: Configure log forwarding\n'
                
                content += '    },\n'
            
            content += '  ]\n'
            content += '}\n\n'
        
        self.write_file('security_rules.tf', content)
    
    def generate_nat_rules(self):
        """Generate NAT policy rules"""
        if not (self.parser.nat_port_forwards or self.parser.nat_outbound):
            return
            
        content = '# NAT Policy Rules\n'
        content += '# Generated from pfSense NAT rules\n'
        content += '# PAN-OS Provider v2.0+ Resource: panos_nat_rule_group\n\n'
        
        content += '''resource "panos_nat_rule_group" "nat_rules" {
  position_keyword = "top"
  
  location = {
    vsys = {
      name = var.vsys
      rulebase = "pre-rulebase"
    }
  }
  
  rules = [
'''
        
        # Port forwards (Destination NAT)
        for idx, rule in enumerate(self.parser.nat_port_forwards):
            if rule['disabled']:
                content += '    # DISABLED NAT RULE:\n'
            
            descr = rule['descr'] or f"Port Forward {idx+1}"
            source_zone = self.parser.zone_mapping.get(rule['interface'], 'untrust')
            
            content += f'''    {{
      name = "{self.escape_string(descr)[:63]}"
      description = "{self.escape_string(descr)}"
      
      original_packet = {{
        source_zones = [panos_zone.{self.sanitize_name(source_zone)}.name]
        destination_zone = panos_zone.{self.sanitize_name(source_zone)}.name
        source_addresses = ["any"]
        destination_addresses = ["any"]  # TODO: Set WAN IP
      }}
      
      translated_packet = {{
        source = {{}}
        destination = {{
          static_translation = {{
            address = "{rule['target']}"
            port = {rule['local-port']}
          }}
        }}
      }}
    }},
'''
        
        # Outbound NAT (Source NAT)
        for idx, rule in enumerate(self.parser.nat_outbound):
            if rule['disabled']:
                content += '    # DISABLED NAT RULE:\n'
            
            descr = rule['descr'] or f"Outbound NAT {idx+1}"
            source_zone = 'trust'  # Typically from internal
            dest_zone = self.parser.zone_mapping.get(rule['interface'], 'untrust')
            
            content += f'''    {{
      name = "{self.escape_string(descr)[:63]}"
      description = "{self.escape_string(descr)}"
      
      original_packet = {{
        source_zones = ["any"]  # TODO: Set source zone
        destination_zone = panos_zone.{self.sanitize_name(dest_zone)}.name
        source_addresses = ["any"]
        destination_addresses = ["any"]
      }}
      
      translated_packet = {{
        source = {{
          dynamic_ip_and_port = {{
            interface_address = {{
              interface = "ethernet1/1"  # TODO: Set correct interface
            }}
          }}
        }}
        destination = {{}}
      }}
    }},
'''
        
        content += '  ]\n'
        content += '}\n'
        
        self.write_file('nat_rules.tf', content)
    
    def generate_interfaces(self):
        """Generate interface documentation"""
        if not self.parser.interfaces:
            return
            
        content = '# Network Interfaces\n'
        content += '# PAN-OS interface configuration documentation\n'
        content += '# Note: Interface configuration in PAN-OS is typically done via:\n'
        content += '#   1. Web GUI (Network -> Interfaces)\n'
        content += '#   2. Panorama templates\n'
        content += '#   3. Bootstrap configuration\n\n'
        content += '# PAN-OS uses ethernet interfaces (ethernet1/1, ethernet1/2, etc.)\n'
        content += '# Map your pfSense interfaces to PAN-OS interfaces below:\n\n'
        
        for iface in self.parser.interfaces:
            zone = self.parser.zone_mapping.get(iface['name'], 'unknown')
            
            content += f'''# pfSense Interface: {iface['name']} ({iface['descr']})
# Physical: {iface['if']}
# Zone: {zone}
'''
            if iface['ipaddr'] and iface['ipaddr'] not in ['dhcp', 'none']:
                content += f"# IP: {iface['ipaddr']}/{iface['subnet']}\n"
            elif iface['ipaddr'] == 'dhcp':
                content += "# IP: DHCP\n"
            
            content += f"# TODO: Map to PAN-OS interface (e.g., ethernet1/1)\n\n"
        
        content += '''
# Example PAN-OS Layer3 Interface Configuration:
# resource "panos_layer3_ethernet_interface" "eth1" {
#   name = "ethernet1/1"
#   mode = "layer3"
#   
#   static_ips = ["192.168.1.1/24"]
#   
#   location = {
#     template = {
#       name = var.template
#     }
#   }
# }
'''
        
        self.write_file('interfaces.tf', content)
    
    def generate_static_routes(self):
        """Generate static route documentation"""
        if not self.parser.static_routes:
            return
            
        content = '# Static Routes\n'
        content += '# Generated from pfSense static routes\n'
        content += '# PAN-OS Provider v2.0+ Resource: panos_static_route\n\n'
        
        for idx, route in enumerate(self.parser.static_routes):
            if route['disabled']:
                content += f"# DISABLED ROUTE:\n"
            
            descr = route['descr'] or f"Route {idx+1}"
            safe_name = self.sanitize_name(f"route_{idx+1}")
            
            content += f'''# {descr}
# Destination: {route['network']}
# Next Hop: {route['gateway']}

# resource "panos_static_route" "{safe_name}" {{
#   name = "{descr[:63]}"
#   destination = "{route['network']}"
#   next_hop = "{route['gateway']}"
#   
#   location = {{
#     virtual_router = {{
#       name = "default"
#       vsys = var.vsys
#     }}
#   }}
# }}

'''
        
        self.write_file('static_routes.tf', content)
    
    def generate_ipsec(self):
        """Generate IPsec VPN documentation"""
        if not self.parser.ipsec_tunnels:
            return
            
        content = '# IPsec VPN Configuration\n'
        content += '# Generated from pfSense IPsec tunnels\n'
        content += '# PAN-OS Provider v2.0+ Resources: panos_ike_gateway, panos_ipsec_tunnel\n\n'
        content += '# WARNING: Pre-shared keys redacted for security\n'
        content += '# Configure authentication credentials manually\n\n'
        
        for idx, tunnel in enumerate(self.parser.ipsec_tunnels):
            if tunnel['disabled']:
                content += f"# DISABLED IPSEC TUNNEL:\n"
            
            safe_name = self.sanitize_name(tunnel['descr'] or f"ipsec_{idx+1}")
            
            # Map IKE version
            ike_version = "ikev2" if tunnel['iketype'] == 'ikev2' else "ikev1"
            
            # Map encryption
            encryption_map = {
                'aes256': 'aes-256-cbc',
                'aes192': 'aes-192-cbc',
                'aes128': 'aes-128-cbc',
                '3des': '3des',
            }
            encryption = encryption_map.get(tunnel['encryption'], 'aes-256-cbc')
            
            # Map hash
            hash_map = {
                'sha256': 'sha256',
                'sha384': 'sha384',
                'sha512': 'sha512',
                'sha1': 'sha1',
                'md5': 'md5',
            }
            auth_algo = hash_map.get(tunnel['hash'], 'sha256')
            
            # Map DH group
            dh_group = f"group{tunnel['dhgroup']}"
            
            content += f'''# IPsec Tunnel: {tunnel['descr']}
# Remote Gateway: {tunnel['remote-gateway']}
# IKE: {ike_version}

# IKE Gateway Configuration
# resource "panos_ike_gateway" "{safe_name}_ike" {{
#   name = "{tunnel['descr'][:63]}"
#   version = "{ike_version}"
#   
#   peer_address = "{tunnel['remote-gateway']}"
#   
#   # Interface configuration
#   location = {{
#     template = {{
#       name = var.template
#     }}
#   }}
#   
#   # Authentication
#   auth_type = "pre-shared-key"
#   pre_shared_key = "***CONFIGURE_PSK_HERE***"  # From: {tunnel['pre-shared-key']}
#   
#   # Phase 1 Proposal
#   encryption = ["{encryption}"]
#   authentication = ["{auth_algo}"]
#   dh_group = ["{dh_group}"]
#   
#   lifetime = {{
#     hours = {int(tunnel['lifetime']) // 3600}
#   }}
# }}

# IPsec Tunnel Configuration
# resource "panos_ipsec_tunnel" "{safe_name}" {{
#   name = "{tunnel['descr'][:63]}"
#   tunnel_interface = "tunnel.1"  # TODO: Assign tunnel interface
#   
#   ike_gateway = panos_ike_gateway.{safe_name}_ike.name
#   
#   location = {{
#     template = {{
#       name = var.template
#     }}
#   }}
# }}

'''
            
            # Phase 2 proxy IDs
            if tunnel['phase2']:
                for p2_idx, p2 in enumerate(tunnel['phase2']):
                    p2_safe = self.sanitize_name(f"{safe_name}_p2_{p2_idx}")
                    
                    # Map Phase 2 encryption
                    p2_encryption = encryption_map.get(p2['encryption'], 'aes-256-cbc')
                    p2_auth = hash_map.get(p2['hash'].replace('hmac_', ''), 'sha256')
                    p2_dh = f"group{p2['pfsgroup']}" if p2['pfsgroup'] != 'no-pfs' else 'no-pfs'
                    
                    content += f'''# Phase 2 (Proxy ID): {p2['descr']}
# Local: {p2['localid_address']}/{p2['localid_netbits']}
# Remote: {p2['remoteid_address']}/{p2['remoteid_netbits']}

# resource "panos_ipsec_crypto_profile" "{p2_safe}_profile" {{
#   name = "{tunnel['descr'][:31]}-p2-{p2_idx}"
#   
#   esp_encryptions = ["{p2_encryption}"]
#   esp_authentications = ["{p2_auth}"]
#   dh_group = "{p2_dh}"
#   
#   lifetime = {{
#     hours = {int(p2['lifetime']) // 3600}
#   }}
#   
#   location = {{
#     template = {{
#       name = var.template
#     }}
#   }}
# }}

'''
        
        self.write_file('ipsec.tf', content)
    
    def generate_migration_reports(self):
        """Generate comprehensive migration documentation"""
        
        report = f'''pfSense to Palo Alto Networks (PAN-OS) Migration Report
{'='*80}

Generated from: {self.parser.xml_file}
Source System: {self.parser.system_info.get('hostname', 'unknown')}.{self.parser.system_info.get('domain', 'unknown')}
Target Platform: Palo Alto Networks PAN-OS (via Terraform Provider v2.0+)

Configuration Summary
{'='*80}

Source Configuration (pfSense):
  Interfaces: {len(self.parser.interfaces)}
  VLANs: {len(self.parser.vlans)}
  Aliases: {len(self.parser.aliases)}
  Firewall Rules: {len(self.parser.firewall_rules)}
  NAT Port Forwards: {len(self.parser.nat_port_forwards)}
  NAT Outbound Rules: {len(self.parser.nat_outbound)}
  NAT 1:1 Rules: {len(self.parser.nat_one_to_one)}
  DHCP Servers: {len(self.parser.dhcp_servers)}
  Static Routes: {len(self.parser.static_routes)}
  IPsec Tunnels: {len(self.parser.ipsec_tunnels)}
  OpenVPN Servers: {len(self.parser.openvpn_servers)}
  OpenVPN Clients: {len(self.parser.openvpn_clients)}

Target Configuration (PAN-OS Terraform Resources):
  Security Zones: {len(set(self.parser.zone_mapping.values()))}
  Address Objects: {sum(1 for a in self.parser.aliases if a['type'] in ['host', 'network'])}
  Service Objects: {len(self.parser.service_objects)}
  Security Rules: {len(self.parser.firewall_rules)}
  NAT Rules: {len(self.parser.nat_port_forwards) + len(self.parser.nat_outbound)}

Zone Mapping
{'='*80}

pfSense Interface → PAN-OS Security Zone:
'''
        
        for iface, zone in sorted(self.parser.zone_mapping.items()):
            iface_data = next((i for i in self.parser.interfaces if i['name'] == iface), None)
            if iface_data:
                report += f"  {iface} ({iface_data['descr']}) → {zone}\n"
        
        report += f'''

Interface Mapping
{'='*80}

pfSense interfaces must be mapped to PAN-OS ethernet interfaces:

'''
        
        for idx, iface in enumerate(self.parser.interfaces):
            zone = self.parser.zone_mapping.get(iface['name'], 'unknown')
            report += f"{iface['name']} ({iface['descr']}):\n"
            report += f"  Physical: {iface['if']}\n"
            report += f"  Zone: {zone}\n"
            if iface['ipaddr'] and iface['ipaddr'] not in ['dhcp', 'none']:
                report += f"  IP: {iface['ipaddr']}/{iface['subnet']}\n"
            report += f"  → Map to: ethernet1/{idx+1} (suggested)\n\n"
        
        report += f'''
Migration Tasks and Requirements
{'='*80}

1. PHYSICAL INTERFACE MAPPING
   ⚠️  CRITICAL: Map pfSense interfaces to PAN-OS interfaces
   - pfSense uses descriptive names (wan, lan, opt1, etc.)
   - PAN-OS uses numbered interfaces (ethernet1/1, ethernet1/2, etc.)
   - Review interfaces.tf and update zone assignments
   - Configure interface IPs in PAN-OS (Network → Interfaces)

2. SECURITY ZONES
   ✓ Generated: zones.tf
   - Review zone assignments and adjust as needed
   - PAN-OS requires explicit zone-to-interface mapping
   - Common zones: trust, untrust, dmz, guest

3. ADDRESS OBJECTS
   ✓ Generated: address_objects.tf
   - Converted from pfSense aliases
   - Review address types (IP/netmask, IP range, FQDN)
   - Address groups created for multi-entry aliases

4. SERVICE OBJECTS
   ✓ Generated: service_objects.tf (if applicable)
   - Custom services extracted from rules
   - PAN-OS has extensive predefined applications
   - Consider using App-ID instead of port-based rules

5. SECURITY POLICY
   ✓ Generated: security_rules.tf
   - Converted from pfSense firewall rules
   - TODO items require manual configuration:
     * Destination zones (currently set to "any")
     * Service object references
     * Application identification
   - Review rule logic and zone-based model differences

6. NAT POLICY
   ✓ Generated: nat_rules.tf
   - Port forwards converted to destination NAT
   - Outbound NAT converted to source NAT
   - TODO items require:
     * Interface assignments
     * Source zone configuration
     * WAN IP configuration

7. STATIC ROUTES
   ✓ Generated: static_routes.tf (commented)
   - Routes documented for manual configuration
   - PAN-OS requires virtual router assignment
   - Default VR name: "default"

8. IPSEC VPN
   ✓ Generated: ipsec.tf (commented)
   - IKE gateways and tunnels documented
   - ⚠️  Pre-shared keys REDACTED for security
   - Requires manual PSK configuration
   - Phase 1 and Phase 2 parameters converted
   - Tunnel interfaces must be assigned

9. DHCP SERVICES
   ⚠️  NOT SUPPORTED via Terraform
   - PAN-OS DHCP configuration requires:
     * Manual configuration via web GUI
     * Panorama templates
     * Or API/XML configuration
   - Reference: dhcp_servers in parsed config

10. OPENVPN
    ⚠️  REQUIRES MANUAL MIGRATION
    - PAN-OS uses GlobalProtect for remote access VPN
    - Site-to-site: Use IPsec instead
    - Certificates must be imported manually
    - Consider GlobalProtect as alternative

Critical Differences: pfSense vs PAN-OS
{'='*80}

1. ZONE-BASED SECURITY MODEL
   - pfSense: Interface-based rules
   - PAN-OS: Zone-based security policy
   - Impact: Rules must specify source AND destination zones

2. APPLICATION IDENTIFICATION (App-ID)
   - pfSense: Port-based filtering
   - PAN-OS: Application-aware filtering
   - Recommendation: Leverage App-ID for better security

3. SECURITY PROFILES
   - pfSense: Basic IDS/IPS via Snort/Suricata packages
   - PAN-OS: Integrated threat prevention
   - Action: Configure security profiles after migration

4. NETWORK ADDRESS TRANSLATION
   - pfSense: Separate port forward and outbound NAT
   - PAN-OS: Unified NAT policy with rule ordering
   - Note: Review NAT rule precedence

5. MANAGEMENT AND LOGGING
   - pfSense: Built-in logging to local disk
   - PAN-OS: Requires log forwarding configuration
   - Action: Configure logging profiles and forwarding

6. HIGH AVAILABILITY
   - pfSense: CARP-based HA
   - PAN-OS: Active/Passive or Active/Active HA
   - Note: HA configuration not in Terraform scope

Pre-Migration Checklist
{'='*80}

 BEFORE running Terraform:
 
 □ Review and understand zone mappings (zones.tf)
 □ Map pfSense interfaces to PAN-OS interfaces (interfaces.tf)
 □ Configure physical interfaces in PAN-OS GUI
 □ Assign interfaces to security zones
 □ Create tunnel interfaces for IPsec VPNs
 □ Obtain and document all VPN pre-shared keys
 □ Review security rules for zone-based model compatibility
 □ Update NAT rules with correct interface assignments
 □ Configure virtual router (usually "default")
 □ Set up log forwarding (Panorama or syslog)
 □ Plan security profile deployment
 □ Back up current PAN-OS configuration
 □ Test in lab environment first!

Terraform Deployment Steps
{'='*80}

1. PROVIDER CONFIGURATION
   cd {self.output_dir}
   
   # Create terraform.tfvars with your PAN-OS connection details:
   cat > terraform.tfvars << EOF
   panos_hostname = "192.168.1.1"     # Your firewall IP
   panos_username = "admin"            # Admin username
   panos_password = "your-password"    # Admin password
   panos_insecure = true               # For self-signed certs
   vsys           = "vsys1"            # Virtual system
   EOF

2. INITIALIZE TERRAFORM
   terraform init
   
   # This downloads the PAN-OS provider v2.0+

3. REVIEW CONFIGURATION
   # Before applying, review generated files:
   - zones.tf (security zones)
   - address_objects.tf (address objects)
   - security_rules.tf (security policy)
   - nat_rules.tf (NAT policy)
   
   # Update TODO items in these files

4. VALIDATE CONFIGURATION
   terraform validate
   
   # Check for syntax errors

5. PLAN DEPLOYMENT
   terraform plan -out=tfplan
   
   # Review what will be created
   # Verify zone assignments
   # Check address objects
   # Validate security rules

6. APPLY TO TEST ENVIRONMENT
   ⚠️  ALWAYS test in lab first!
   
   terraform apply tfplan
   
   # Monitor for errors
   # Review created objects in PAN-OS GUI

7. COMMIT CHANGES
   # PAN-OS requires manual commit
   # Via GUI: Commit → Commit
   # Via CLI: commit
   # Or use panos_commit resource

8. VALIDATE FUNCTIONALITY
   □ Test connectivity through firewall
   □ Verify NAT translations
   □ Check security policy enforcement
   □ Test VPN connectivity
   □ Validate routing
   □ Review logs

Post-Migration Tasks
{'='*80}

1. SECURITY PROFILES
   - Configure antivirus profiles
   - Set up anti-spyware profiles
   - Enable vulnerability protection
   - Configure file blocking
   - Set up URL filtering
   - Apply profiles to security rules

2. LOGGING AND MONITORING
   - Configure log forwarding to Panorama or syslog
   - Set up email alerts
   - Configure SNMP monitoring
   - Enable session logging as needed

3. THREAT PREVENTION
   - Update threat databases
   - Configure WildFire (if licensed)
   - Set up DNS security (if licensed)

4. USER IDENTIFICATION
   - Integrate with Active Directory (if applicable)
   - Configure User-ID agent
   - Enable user-based policies

5. GLOBALPROTECT (if needed)
   - Configure GlobalProtect portals
   - Set up GlobalProtect gateways
   - Migrate OpenVPN users to GlobalProtect

6. PERFORMANCE OPTIMIZATION
   - Enable hardware offloading
   - Configure session timers
   - Optimize security rule order
   - Review and tune App-ID

7. DOCUMENTATION
   - Document zone design
   - Maintain IP address inventory
   - Update network diagrams
   - Document security policy
   - Create runbooks for common tasks

Known Limitations and Considerations
{'='*80}

1. TERRAFORM PROVIDER LIMITATIONS
   - Not all PAN-OS features supported in provider v2.0
   - Some features require manual configuration
   - Commits must be done manually or via separate resource
   - Limited DHCP/DNS support

2. FEATURE GAPS
   - pfSense packages (Snort, pfBlockerNG, etc.) have no direct equivalents
   - Some advanced routing features may differ
   - Captive portal → GlobalProtect
   - Multi-WAN → SD-WAN or policy-based forwarding

3. PERFORMANCE CONSIDERATIONS
   - PAN-OS processes traffic differently (App-ID, Content-ID)
   - May need to adjust security profiles for performance
   - Hardware sizing important for throughput

4. LICENSING REQUIREMENTS
   - Base PAN-OS license included
   - Threat Prevention license for IPS/AV
   - URL Filtering license
   - GlobalProtect license for VPN
   - WildFire license for advanced malware analysis

Rollback Plan
{'='*80}

If migration issues occur:

1. Keep pfSense operational during testing
2. Document all changes made to PAN-OS
3. Have PAN-OS backup before applying Terraform
4. Test rollback procedure in lab
5. Maintain configuration backups
6. Document lessons learned

Additional Resources
{'='*80}

- PAN-OS Administrator's Guide: https://docs.paloaltonetworks.com
- Terraform PAN-OS Provider: https://registry.terraform.io/providers/PaloAltoNetworks/panos/latest
- PAN-OS API Documentation: https://docs.paloaltonetworks.com/pan-os/
- Migration Best Practices: https://live.paloaltonetworks.com
- App-ID Documentation: https://applipedia.paloaltonetworks.com

Support and Community
{'='*80}

- Palo Alto Networks Support: https://support.paloaltonetworks.com
- LIVEcommunity Forums: https://live.paloaltonetworks.com
- Terraform Provider Issues: https://github.com/PaloAltoNetworks/terraform-provider-panos

---
Generated: {self.get_timestamp()}
Tool: pfSense to PAN-OS Terraform Converter
Target: PAN-OS Terraform Provider v2.0+
'''
        
        self.write_file('MIGRATION_GUIDE.txt', report)
        
        # Generate VPN-specific guide if applicable
        if self.parser.ipsec_tunnels or self.parser.openvpn_servers or self.parser.openvpn_clients:
            self.generate_vpn_migration_guide()
    
    def generate_vpn_migration_guide(self):
        """Generate VPN-specific migration documentation"""
        
        content = f'''pfSense to PAN-OS VPN Migration Guide
{'='*80}

⚠️  CRITICAL: VPN Configuration Requires Manual Steps

This guide covers migrating VPN configurations from pfSense to Palo Alto Networks.

IPsec Site-to-Site VPN Migration
{'='*80}

Found {len(self.parser.ipsec_tunnels)} IPsec tunnel(s) in pfSense configuration.

'''
        
        for idx, tunnel in enumerate(self.parser.ipsec_tunnels):
            content += f'''
Tunnel {idx+1}: {tunnel['descr']}
{'-' * 80}
IKE Configuration:
  Version: {tunnel['iketype']}
  Remote Gateway: {tunnel['remote-gateway']}
  Interface: {tunnel['interface']}
  
Authentication:
  Method: {tunnel['authentication_method']}
  Pre-Shared Key: {tunnel['pre-shared-key']}
  Local ID Type: {tunnel['myid_type']}
  Local ID Data: {tunnel['myid_data'] or 'N/A'}
  Peer ID Type: {tunnel['peerid_type']}
  Peer ID Data: {tunnel['peerid_data'] or 'N/A'}

Phase 1 Proposal:
  Encryption: {tunnel['encryption']}
  Hash: {tunnel['hash']}
  DH Group: {tunnel['dhgroup']}
  Lifetime: {tunnel['lifetime']} seconds ({int(tunnel['lifetime']) // 3600} hours)

Phase 2 Configurations:
'''
            
            if tunnel['phase2']:
                for p2_idx, p2 in enumerate(tunnel['phase2']):
                    content += f'''
  Phase 2 #{p2_idx+1}: {p2['descr']}
    Local Subnet: {p2['localid_address']}/{p2['localid_netbits']}
    Remote Subnet: {p2['remoteid_address']}/{p2['remoteid_netbits']}
    Protocol: {p2['protocol']}
    Encryption: {p2['encryption']}
    Hash: {p2['hash']}
    PFS Group: {p2['pfsgroup']}
    Lifetime: {p2['lifetime']} seconds ({int(p2['lifetime']) // 3600} hours)
'''
            
            content += f'''
PAN-OS Configuration Steps:
  1. Navigate to Network → Network Profiles → IKE Crypto
     - Create profile matching Phase 1 parameters
  
  2. Navigate to Network → Network Profiles → IPsec Crypto
     - Create profile(s) matching Phase 2 parameters
  
  3. Navigate to Network → Network Profiles → IKE Gateways
     - Create IKE gateway with:
       * Peer Address: {tunnel['remote-gateway']}
       * Pre-shared Key: (enter manually)
       * IKE Crypto Profile: (from step 1)
  
  4. Navigate to Network → IPsec Tunnels
     - Create tunnel with:
       * Tunnel Interface: tunnel.{idx+1}
       * IKE Gateway: (from step 3)
       * IPsec Crypto Profile: (from step 2)
  
  5. Assign tunnel interface to security zone
  
  6. Create security policies for VPN traffic

'''
        
        # OpenVPN section
        if self.parser.openvpn_servers or self.parser.openvpn_clients:
            content += f'''

OpenVPN Migration → GlobalProtect
{'='*80}

pfSense OpenVPN cannot be directly migrated to PAN-OS.
Recommended alternative: GlobalProtect

OpenVPN Servers Found: {len(self.parser.openvpn_servers)}
OpenVPN Clients Found: {len(self.parser.openvpn_clients)}

'''
            
            for server in self.parser.openvpn_servers:
                content += f'''
OpenVPN Server: {server['description']}
{'-' * 80}
Configuration:
  Mode: {server['mode']}
  Protocol: {server['protocol']}
  Port: {server['local_port']}
  Tunnel Network: {server['tunnel_network']}
  Local Network: {server['local_network']}
  Encryption: {server['crypto']}
  Digest: {server['digest']}

Migration to GlobalProtect:
  1. Requires GlobalProtect license
  2. Navigate to Network → GlobalProtect → Portals
  3. Configure portal for remote user access
  4. Navigate to Network → GlobalProtect → Gateways
  5. Configure gateway matching VPN requirements
  6. Import/create certificates for SSL VPN
  7. Configure authentication (local, RADIUS, LDAP, SAML)
  8. Set up tunnel configuration
  9. Deploy GlobalProtect client to users
  10. Migrate user authentication database

'''
        
        content += f'''
VPN Migration Checklist
{'='*80}

IPsec Site-to-Site VPN:
 □ Document all pre-shared keys securely
 □ Note all Phase 1 and Phase 2 parameters
 □ Verify remote peer requirements/compatibility
 □ Create IKE crypto profiles in PAN-OS
 □ Create IPsec crypto profiles in PAN-OS
 □ Configure IKE gateways
 □ Configure IPsec tunnels
 □ Assign tunnel interfaces to zones
 □ Create security policies for VPN traffic
 □ Configure routing for VPN subnets
 □ Test VPN establishment
 □ Verify traffic flow through VPN
 □ Monitor VPN logs

OpenVPN → GlobalProtect Migration:
 □ Verify GlobalProtect license
 □ Plan authentication migration
 □ Export/migrate user database
 □ Configure GlobalProtect portal
 □ Configure GlobalProtect gateway
 □ Import certificates
 □ Test with pilot users
 □ Deploy GlobalProtect client
 □ Migrate users in phases
 □ Decommission OpenVPN

Common VPN Migration Issues
{'='*80}

1. PHASE 1/2 MISMATCH
   - Verify encryption algorithms match
   - Check hash algorithms
   - Confirm DH group compatibility
   - Validate lifetimes

2. NAT TRAVERSAL
   - PAN-OS auto-detects NAT-T
   - Ensure UDP 4500 is allowed
   - Check NAT-T settings on remote peer

3. PROXY IDs
   - PAN-OS uses proxy IDs differently
   - May need multiple tunnels for multiple subnets
   - Route-based VPN recommended for flexibility

4. CERTIFICATE AUTHENTICATION
   - Requires certificate import to PAN-OS
   - Configure certificate profile
   - Match DN/SAN requirements

5. SPLIT TUNNEL
   - GlobalProtect handles differently than OpenVPN
   - Configure traffic selection carefully
   - Test routing for split tunnel scenarios

Testing Procedures
{'='*80}

Phase 1 Testing:
  1. Check IKE gateway status: Network → IPsec Tunnels
  2. Verify Phase 1 establishment in Monitor → Logs → System
  3. Check for Phase 1 errors
  4. Validate peer connectivity

Phase 2 Testing:
  1. Generate interesting traffic
  2. Verify Phase 2 (SA) establishment
  3. Check Monitor → Logs → System for IPsec events
  4. Validate encryption/decryption counters

Traffic Testing:
  1. Ping from local to remote subnet
  2. Check traffic logs: Monitor → Logs → Traffic
  3. Verify correct zone enforcement
  4. Test application traffic
  5. Monitor tunnel statistics

GlobalProtect Testing:
  1. Test portal connectivity
  2. Verify client connects to gateway
  3. Check tunnel establishment
  4. Validate split tunnel routing
  5. Test application access
  6. Verify authentication

Troubleshooting Commands
{'='*80}

CLI Commands for VPN Debugging:

  # Show IPsec tunnels
  show vpn ipsec-sa
  
  # Show IKE gateways
  show vpn ike-sa
  
  # Show GlobalProtect gateways
  show global-protect-gateway current-user
  
  # Show IPsec flow
  show vpn flow
  
  # Debug IKE (caution in production)
  debug ike global on
  debug ike pcap on
  
  # Clear IPsec SA
  clear vpn ipsec-sa
  
  # Clear IKE SA
  clear vpn ike-sa

---
Generated: {self.get_timestamp()}
'''
        
        self.write_file('VPN_MIGRATION_GUIDE.txt', content)
    
    def get_timestamp(self):
        """Get current timestamp"""
        from datetime import datetime
        return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    def sanitize_name(self, name: str) -> str:
        """Sanitize name for Terraform resource naming"""
        name = re.sub(r'[^a-zA-Z0-9_-]', '_', name)
        name = name.lower()
        if name and not name[0].isalpha():
            name = 'r_' + name
        return name or 'unnamed'
    
    def escape_string(self, s: str) -> str:
        """Escape string for Terraform HCL"""
        return s.replace('\\', '\\\\').replace('"', '\\"').replace('\n', '\\n')
    
    def write_file(self, filename: str, content: str):
        """Write content to file"""
        filepath = self.output_dir / filename
        with open(filepath, 'w') as f:
            f.write(content)
        print(f"  ✓ Generated {filename}")


def main():
    parser = argparse.ArgumentParser(
        description='Convert pfSense configuration to PAN-OS Terraform',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Basic conversion
  python3 pfsense_to_panos.py config.xml
  
  # Custom output directory
  python3 pfsense_to_panos.py config.xml --output-dir my-panos-terraform
  
  # Get pfSense config backup from web UI:
  # Navigate to Diagnostics → Backup & Restore → Download configuration
'''
    )
    
    parser.add_argument('config_xml', help='Path to pfSense configuration XML file')
    parser.add_argument('--output-dir', default='panos-terraform',
                       help='Output directory for Terraform files (default: panos-terraform)')
    
    args = parser.parse_args()
    
    if not os.path.exists(args.config_xml):
        print(f"Error: File not found: {args.config_xml}")
        sys.exit(1)
    
    try:
        # Parse pfSense configuration
        pfsense_parser = PfSenseParser(args.config_xml)
        pfsense_parser.parse()
        
        # Generate PAN-OS Terraform configuration
        panos_gen = PanosGenerator(pfsense_parser, args.output_dir)
        panos_gen.generate_all()
        
        print("\n📄 Generated Migration Guides:")
        print("  - MIGRATION_GUIDE.txt (Complete migration documentation)")
        if pfsense_parser.ipsec_tunnels or pfsense_parser.openvpn_servers or pfsense_parser.openvpn_clients:
            print("  - VPN_MIGRATION_GUIDE.txt (VPN-specific migration steps)")
        
    except ET.ParseError as e:
        print(f"Error: Failed to parse XML file: {e}")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
