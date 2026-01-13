# Service Objects
# Generated from pfSense firewall rules
# PAN-OS Provider v2.0+ Resource: panos_service_object

resource "panos_service_object" "webports_80" {
  name = "WebPorts-80"
  
  location = {
    vsys = {
      name = var.vsys
    }
  }
  
  protocol = {
    tcp = {
      port = "80"
    }
  }
  
  description = "Common web service ports"
}

resource "panos_service_object" "webports_443" {
  name = "WebPorts-443"
  
  location = {
    vsys = {
      name = var.vsys
    }
  }
  
  protocol = {
    tcp = {
      port = "443"
    }
  }
  
  description = "Common web service ports"
}

resource "panos_service_object" "webports_8080" {
  name = "WebPorts-8080"
  
  location = {
    vsys = {
      name = var.vsys
    }
  }
  
  protocol = {
    tcp = {
      port = "8080"
    }
  }
  
  description = "Common web service ports"
}

resource "panos_service_object" "webports_8443" {
  name = "WebPorts-8443"
  
  location = {
    vsys = {
      name = var.vsys
    }
  }
  
  protocol = {
    tcp = {
      port = "8443"
    }
  }
  
  description = "Common web service ports"
}

