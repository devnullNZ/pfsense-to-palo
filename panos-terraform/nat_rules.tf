# NAT Policy Rules
# Generated from pfSense NAT rules
# PAN-OS Provider v2.0+ Resource: panos_nat_rule_group

resource "panos_nat_rule_group" "nat_rules" {
  position_keyword = "top"
  
  location = {
    vsys = {
      name = var.vsys
      rulebase = "pre-rulebase"
    }
  }
  
  rules = [
    {
      name = "HTTP to WebServer1"
      description = "HTTP to WebServer1"
      
      original_packet = {
        source_zones = [panos_zone.untrust.name]
        destination_zone = panos_zone.untrust.name
        source_addresses = ["any"]
        destination_addresses = ["any"]  # TODO: Set WAN IP
      }
      
      translated_packet = {
        source = {}
        destination = {
          static_translation = {
            address = "10.0.10.10"
            port = 80
          }
        }
      }
    },
    {
      name = "HTTPS to WebServer1"
      description = "HTTPS to WebServer1"
      
      original_packet = {
        source_zones = [panos_zone.untrust.name]
        destination_zone = panos_zone.untrust.name
        source_addresses = ["any"]
        destination_addresses = ["any"]  # TODO: Set WAN IP
      }
      
      translated_packet = {
        source = {}
        destination = {
          static_translation = {
            address = "10.0.10.10"
            port = 443
          }
        }
      }
    },
    {
      name = "SSH to admin host"
      description = "SSH to admin host"
      
      original_packet = {
        source_zones = [panos_zone.untrust.name]
        destination_zone = panos_zone.untrust.name
        source_addresses = ["any"]
        destination_addresses = ["any"]  # TODO: Set WAN IP
      }
      
      translated_packet = {
        source = {}
        destination = {
          static_translation = {
            address = "192.168.1.10"
            port = 22
          }
        }
      }
    },
    {
      name = "LAN to WAN NAT"
      description = "LAN to WAN NAT"
      
      original_packet = {
        source_zones = ["any"]  # TODO: Set source zone
        destination_zone = panos_zone.untrust.name
        source_addresses = ["any"]
        destination_addresses = ["any"]
      }
      
      translated_packet = {
        source = {
          dynamic_ip_and_port = {
            interface_address = {
              interface = "ethernet1/1"  # TODO: Set correct interface
            }
          }
        }
        destination = {}
      }
    },
    {
      name = "DMZ to WAN NAT"
      description = "DMZ to WAN NAT"
      
      original_packet = {
        source_zones = ["any"]  # TODO: Set source zone
        destination_zone = panos_zone.untrust.name
        source_addresses = ["any"]
        destination_addresses = ["any"]
      }
      
      translated_packet = {
        source = {
          dynamic_ip_and_port = {
            interface_address = {
              interface = "ethernet1/1"  # TODO: Set correct interface
            }
          }
        }
        destination = {}
      }
    },
    {
      name = "Guest to WAN NAT"
      description = "Guest to WAN NAT"
      
      original_packet = {
        source_zones = ["any"]  # TODO: Set source zone
        destination_zone = panos_zone.untrust.name
        source_addresses = ["any"]
        destination_addresses = ["any"]
      }
      
      translated_packet = {
        source = {
          dynamic_ip_and_port = {
            interface_address = {
              interface = "ethernet1/1"  # TODO: Set correct interface
            }
          }
        }
        destination = {}
      }
    },
  ]
}
