# IPsec VPN Configuration
# Generated from pfSense IPsec tunnels
# PAN-OS Provider v2.0+ Resources: panos_ike_gateway, panos_ipsec_tunnel

# WARNING: Pre-shared keys redacted for security
# Configure authentication credentials manually

# IPsec Tunnel: VPN to Remote Office
# Remote Gateway: 203.0.113.50
# IKE: ikev2

# IKE Gateway Configuration
# resource "panos_ike_gateway" "vpn_to_remote_office_ike" {
#   name = "VPN to Remote Office"
#   version = "ikev2"
#   
#   peer_address = "203.0.113.50"
#   
#   # Interface configuration
#   location = {
#     template = {
#       name = var.template
#     }
#   }
#   
#   # Authentication
#   auth_type = "pre-shared-key"
#   pre_shared_key = "***CONFIGURE_PSK_HERE***"  # From: MySecretPreSharedKey123
#   
#   # Phase 1 Proposal
#   encryption = ["aes-256-cbc"]
#   authentication = ["sha256"]
#   dh_group = ["group14"]
#   
#   lifetime = {
#     hours = 8
#   }
# }

# IPsec Tunnel Configuration
# resource "panos_ipsec_tunnel" "vpn_to_remote_office" {
#   name = "VPN to Remote Office"
#   tunnel_interface = "tunnel.1"  # TODO: Assign tunnel interface
#   
#   ike_gateway = panos_ike_gateway.vpn_to_remote_office_ike.name
#   
#   location = {
#     template = {
#       name = var.template
#     }
#   }
# }

# Phase 2 (Proxy ID): Remote Office Tunnel
# Local: 192.168.1.0/24
# Remote: 10.99.0.0/24

# resource "panos_ipsec_crypto_profile" "vpn_to_remote_office_p2_0_profile" {
#   name = "VPN to Remote Office-p2-0"
#   
#   esp_encryptions = ["aes-256-cbc"]
#   esp_authentications = ["sha256"]
#   dh_group = "group14"
#   
#   lifetime = {
#     hours = 1
#   }
#   
#   location = {
#     template = {
#       name = var.template
#     }
#   }
# }

# IPsec Tunnel: VPN to Datacenter
# Remote Gateway: 198.51.100.75
# IKE: ikev2

# IKE Gateway Configuration
# resource "panos_ike_gateway" "vpn_to_datacenter_ike" {
#   name = "VPN to Datacenter"
#   version = "ikev2"
#   
#   peer_address = "198.51.100.75"
#   
#   # Interface configuration
#   location = {
#     template = {
#       name = var.template
#     }
#   }
#   
#   # Authentication
#   auth_type = "pre-shared-key"
#   pre_shared_key = "***CONFIGURE_PSK_HERE***"  # From: AnotherSecretKey456
#   
#   # Phase 1 Proposal
#   encryption = ["aes-256-cbc"]
#   authentication = ["sha256"]
#   dh_group = ["group14"]
#   
#   lifetime = {
#     hours = 8
#   }
# }

# IPsec Tunnel Configuration
# resource "panos_ipsec_tunnel" "vpn_to_datacenter" {
#   name = "VPN to Datacenter"
#   tunnel_interface = "tunnel.1"  # TODO: Assign tunnel interface
#   
#   ike_gateway = panos_ike_gateway.vpn_to_datacenter_ike.name
#   
#   location = {
#     template = {
#       name = var.template
#     }
#   }
# }

# Phase 2 (Proxy ID): Datacenter Tunnel
# Local: 192.168.1.0/24
# Remote: 172.16.0.0/16

# resource "panos_ipsec_crypto_profile" "vpn_to_datacenter_p2_0_profile" {
#   name = "VPN to Datacenter-p2-0"
#   
#   esp_encryptions = ["aes-256-cbc"]
#   esp_authentications = ["sha256"]
#   dh_group = "group14"
#   
#   lifetime = {
#     hours = 1
#   }
#   
#   location = {
#     template = {
#       name = var.template
#     }
#   }
# }

