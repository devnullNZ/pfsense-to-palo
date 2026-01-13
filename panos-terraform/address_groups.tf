# Address Groups
# Generated from pfSense aliases with multiple entries
# PAN-OS Provider v2.0+ Resource: panos_address_group

resource "panos_address_group" "rfc1918_networks_group" {
  name = "RFC1918_Networks"
  
  location = {
    vsys = {
      name = var.vsys
    }
  }
  
  static_addresses = [
    panos_address_object.rfc1918_networks_0.name,
    panos_address_object.rfc1918_networks_1.name,
    panos_address_object.rfc1918_networks_2.name,
  ]
  description = "Private IPv4 address space"
}

resource "panos_address_group" "webservers_group" {
  name = "WebServers"
  
  location = {
    vsys = {
      name = var.vsys
    }
  }
  
  static_addresses = [
    panos_address_object.webservers_0.name,
    panos_address_object.webservers_1.name,
    panos_address_object.webservers_2.name,
  ]
  description = "DMZ web servers"
}

resource "panos_address_group" "databaseservers_group" {
  name = "DatabaseServers"
  
  location = {
    vsys = {
      name = var.vsys
    }
  }
  
  static_addresses = [
    panos_address_object.databaseservers_0.name,
    panos_address_object.databaseservers_1.name,
  ]
  description = "DMZ database servers"
}

resource "panos_address_group" "managementhosts_group" {
  name = "ManagementHosts"
  
  location = {
    vsys = {
      name = var.vsys
    }
  }
  
  static_addresses = [
    panos_address_object.managementhosts_0.name,
    panos_address_object.managementhosts_1.name,
  ]
  description = "Admin workstations"
}

