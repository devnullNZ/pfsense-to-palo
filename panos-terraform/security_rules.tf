# Security Policy Rules
# Generated from pfSense firewall rules
# PAN-OS Provider v2.0+ Resource: panos_security_rule_group

# Security rules for zone: dmz
resource "panos_security_rule_group" "rules_dmz" {
  position_keyword = "top"
  
  location = {
    vsys = {
      name = var.vsys
      rulebase = "pre-rulebase"
    }
  }
  
  rules = [
    {
      name        = "Allow web servers to database"  # Max 63 chars
      action      = "allow"
      description = "Allow web servers to database"
      source_zones = [panos_zone.dmz.name]
      source_addresses = ["WebServers"]
      destination_zones = ["any"]  # TODO: Set appropriate destination zone
      destination_addresses = ["DatabaseServers"]
      applications = ["application-default"]
      services = ["service-tcp-3306"]  # TODO: Create service object
    },
    {
      name        = "Allow admin SSH to web servers"  # Max 63 chars
      action      = "allow"
      description = "Allow admin SSH to web servers"
      source_zones = [panos_zone.dmz.name]
      source_addresses = ["ManagementHosts"]
      destination_zones = ["any"]  # TODO: Set appropriate destination zone
      destination_addresses = ["WebServers"]
      applications = ["application-default"]
      services = ["service-tcp-22"]  # TODO: Create service object
    },
    {
      name        = "Block DMZ to private networks"  # Max 63 chars
      action      = "deny"
      description = "Block DMZ to private networks"
      source_zones = [panos_zone.dmz.name]
      source_addresses = ["opt1"]
      destination_zones = ["any"]  # TODO: Set appropriate destination zone
      destination_addresses = ["RFC1918_Networks"]
      applications = ["any"]
      services = ["application-default"]
      log_setting = "default"  # TODO: Configure log forwarding
    },
  ]
}

# Security rules for zone: guest
resource "panos_security_rule_group" "rules_guest" {
  position_keyword = "top"
  
  location = {
    vsys = {
      name = var.vsys
      rulebase = "pre-rulebase"
    }
  }
  
  rules = [
    {
      name        = "Allow guest DNS"  # Max 63 chars
      action      = "allow"
      description = "Allow guest DNS"
      source_zones = [panos_zone.guest.name]
      source_addresses = ["opt2"]
      destination_zones = ["any"]  # TODO: Set appropriate destination zone
      destination_addresses = ["any"]
      applications = ["any"]
      services = ["application-default"]
    },
    {
      name        = "Allow guest HTTP"  # Max 63 chars
      action      = "allow"
      description = "Allow guest HTTP"
      source_zones = [panos_zone.guest.name]
      source_addresses = ["opt2"]
      destination_zones = ["any"]  # TODO: Set appropriate destination zone
      destination_addresses = ["any"]
      applications = ["application-default"]
      services = ["application-default"]
    },
    {
      name        = "Allow guest HTTPS"  # Max 63 chars
      action      = "allow"
      description = "Allow guest HTTPS"
      source_zones = [panos_zone.guest.name]
      source_addresses = ["opt2"]
      destination_zones = ["any"]  # TODO: Set appropriate destination zone
      destination_addresses = ["any"]
      applications = ["application-default"]
      services = ["application-default"]
    },
    {
      name        = "Block guest to private networks"  # Max 63 chars
      action      = "deny"
      description = "Block guest to private networks"
      source_zones = [panos_zone.guest.name]
      source_addresses = ["opt2"]
      destination_zones = ["any"]  # TODO: Set appropriate destination zone
      destination_addresses = ["RFC1918_Networks"]
      applications = ["any"]
      services = ["application-default"]
      log_setting = "default"  # TODO: Configure log forwarding
    },
  ]
}

# Security rules for zone: trust
resource "panos_security_rule_group" "rules_trust" {
  position_keyword = "top"
  
  location = {
    vsys = {
      name = var.vsys
      rulebase = "pre-rulebase"
    }
  }
  
  rules = [
    {
      name        = "Allow LAN to any"  # Max 63 chars
      action      = "allow"
      description = "Allow LAN to any"
      source_zones = [panos_zone.trust.name]
      source_addresses = ["lan"]
      destination_zones = ["any"]  # TODO: Set appropriate destination zone
      destination_addresses = ["any"]
      applications = ["any"]
      services = ["application-default"]
    },
  ]
}

# Security rules for zone: untrust
resource "panos_security_rule_group" "rules_untrust" {
  position_keyword = "top"
  
  location = {
    vsys = {
      name = var.vsys
      rulebase = "pre-rulebase"
    }
  }
  
  rules = [
    {
      name        = "Allow web traffic to DMZ servers"  # Max 63 chars
      action      = "allow"
      description = "Allow web traffic to DMZ servers"
      source_zones = [panos_zone.untrust.name]
      source_addresses = ["any"]
      destination_zones = ["any"]  # TODO: Set appropriate destination zone
      destination_addresses = ["WebServers"]
      applications = ["application-default"]
      services = ["service-tcp-WebPorts"]  # TODO: Create service object
      log_setting = "default"  # TODO: Configure log forwarding
    },
  ]
}

