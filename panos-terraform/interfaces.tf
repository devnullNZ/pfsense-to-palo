# Network Interfaces
# PAN-OS interface configuration documentation
# Note: Interface configuration in PAN-OS is typically done via:
#   1. Web GUI (Network -> Interfaces)
#   2. Panorama templates
#   3. Bootstrap configuration

# PAN-OS uses ethernet interfaces (ethernet1/1, ethernet1/2, etc.)
# Map your pfSense interfaces to PAN-OS interfaces below:

# pfSense Interface: wan (WAN)
# Physical: igb0
# Zone: untrust
# IP: DHCP
# TODO: Map to PAN-OS interface (e.g., ethernet1/1)

# pfSense Interface: lan (LAN)
# Physical: igb1
# Zone: trust
# IP: 192.168.1.1/24
# TODO: Map to PAN-OS interface (e.g., ethernet1/1)

# pfSense Interface: opt1 (DMZ)
# Physical: igb2
# Zone: dmz
# IP: 10.0.10.1/24
# TODO: Map to PAN-OS interface (e.g., ethernet1/1)

# pfSense Interface: opt2 (GUEST)
# Physical: igb3
# Zone: guest
# IP: 10.0.20.1/24
# TODO: Map to PAN-OS interface (e.g., ethernet1/1)


# Example PAN-OS Layer3 Interface Configuration:
# resource "panos_layer3_ethernet_interface" "eth1" {
#   name = "ethernet1/1"
#   mode = "layer3"
#   
#   static_ips = ["192.168.1.1/24"]
#   
#   location = {
#     template = {
#       name = var.template
#     }
#   }
# }
