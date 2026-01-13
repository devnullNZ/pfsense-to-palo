# Terraform Provider Configuration for PAN-OS
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
