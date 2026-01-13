# Variables for PAN-OS Terraform Configuration

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
