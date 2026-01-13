# Static Routes
# Generated from pfSense static routes
# PAN-OS Provider v2.0+ Resource: panos_static_route

# Route to remote office network
# Destination: 10.99.0.0/24
# Next Hop: 192.168.1.254

# resource "panos_static_route" "route_1" {
#   name = "Route to remote office network"
#   destination = "10.99.0.0/24"
#   next_hop = "192.168.1.254"
#   
#   location = {
#     virtual_router = {
#       name = "default"
#       vsys = var.vsys
#     }
#   }
# }

# Route to datacenter network
# Destination: 172.16.0.0/16
# Next Hop: 192.168.1.253

# resource "panos_static_route" "route_2" {
#   name = "Route to datacenter network"
#   destination = "172.16.0.0/16"
#   next_hop = "192.168.1.253"
#   
#   location = {
#     virtual_router = {
#       name = "default"
#       vsys = var.vsys
#     }
#   }
# }

