# Address Objects
# Generated from pfSense aliases
# PAN-OS Provider v2.0+ Resource: panos_address_object

resource "panos_address_object" "rfc1918_networks_0" {
  name = "RFC1918_Networks"
  
  location = {
    vsys = {
      name = var.vsys
    }
  }
  
  ip_netmask = "10.0.0.0/8"
  description = "Private IPv4 address space"
}

resource "panos_address_object" "rfc1918_networks_1" {
  name = "RFC1918_Networks"
  
  location = {
    vsys = {
      name = var.vsys
    }
  }
  
  ip_netmask = "172.16.0.0/12"
  description = "Private IPv4 address space"
}

resource "panos_address_object" "rfc1918_networks_2" {
  name = "RFC1918_Networks"
  
  location = {
    vsys = {
      name = var.vsys
    }
  }
  
  ip_netmask = "192.168.0.0/16"
  description = "Private IPv4 address space"
}

resource "panos_address_object" "webservers_0" {
  name = "WebServers"
  
  location = {
    vsys = {
      name = var.vsys
    }
  }
  
  ip_netmask = "10.0.10.10/32"
  description = "DMZ web servers"
}

resource "panos_address_object" "webservers_1" {
  name = "WebServers"
  
  location = {
    vsys = {
      name = var.vsys
    }
  }
  
  ip_netmask = "10.0.10.11/32"
  description = "DMZ web servers"
}

resource "panos_address_object" "webservers_2" {
  name = "WebServers"
  
  location = {
    vsys = {
      name = var.vsys
    }
  }
  
  ip_netmask = "10.0.10.12/32"
  description = "DMZ web servers"
}

resource "panos_address_object" "databaseservers_0" {
  name = "DatabaseServers"
  
  location = {
    vsys = {
      name = var.vsys
    }
  }
  
  ip_netmask = "10.0.10.20/32"
  description = "DMZ database servers"
}

resource "panos_address_object" "databaseservers_1" {
  name = "DatabaseServers"
  
  location = {
    vsys = {
      name = var.vsys
    }
  }
  
  ip_netmask = "10.0.10.21/32"
  description = "DMZ database servers"
}

resource "panos_address_object" "managementhosts_0" {
  name = "ManagementHosts"
  
  location = {
    vsys = {
      name = var.vsys
    }
  }
  
  ip_netmask = "192.168.1.10/32"
  description = "Admin workstations"
}

resource "panos_address_object" "managementhosts_1" {
  name = "ManagementHosts"
  
  location = {
    vsys = {
      name = var.vsys
    }
  }
  
  ip_netmask = "192.168.1.11/32"
  description = "Admin workstations"
}

