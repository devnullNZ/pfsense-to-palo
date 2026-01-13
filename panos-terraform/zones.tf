# Security Zones
# Generated from pfSense interface mapping
# PAN-OS Provider v2.0+ Resource: panos_zone

resource "panos_zone" "dmz" {
  name = "dmz"
  mode = "layer3"
  
  location = {
    vsys = {
      name = var.vsys
    }
  }
  
  # Interfaces from pfSense: opt1
  # Note: Map these to actual PAN-OS interfaces (ethernet1/1, etc.)
  # interfaces = ["ethernet1/1"]  # TODO: Update with actual interface names
}

resource "panos_zone" "guest" {
  name = "guest"
  mode = "layer3"
  
  location = {
    vsys = {
      name = var.vsys
    }
  }
  
  # Interfaces from pfSense: opt2
  # Note: Map these to actual PAN-OS interfaces (ethernet1/1, etc.)
  # interfaces = ["ethernet1/1"]  # TODO: Update with actual interface names
}

resource "panos_zone" "trust" {
  name = "trust"
  mode = "layer3"
  
  location = {
    vsys = {
      name = var.vsys
    }
  }
  
  # Interfaces from pfSense: lan
  # Note: Map these to actual PAN-OS interfaces (ethernet1/1, etc.)
  # interfaces = ["ethernet1/1"]  # TODO: Update with actual interface names
}

resource "panos_zone" "untrust" {
  name = "untrust"
  mode = "layer3"
  
  location = {
    vsys = {
      name = var.vsys
    }
  }
  
  # Interfaces from pfSense: wan
  # Note: Map these to actual PAN-OS interfaces (ethernet1/1, etc.)
  # interfaces = ["ethernet1/1"]  # TODO: Update with actual interface names
}

