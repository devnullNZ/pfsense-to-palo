# pfSense to Palo Alto Networks (PAN-OS) Migration Tool

Convert pfSense firewall configurations to Palo Alto Networks using Terraform Provider v2.0+

## 🎯 What This Tool Does

Migrates firewall configurations from **pfSense** to **Palo Alto Networks PAN-OS** using Infrastructure as Code:

- ✅ **Security Zones** - Intelligent interface-to-zone mapping
- ✅ **Address Objects** - Converts pfSense aliases to PAN address objects
- ✅ **Address Groups** - Creates groups from multi-entry aliases
- ✅ **Service Objects** - Extracts custom services from rules
- ✅ **Security Policy** - Converts firewall rules to zone-based security rules
- ✅ **NAT Policy** - Migrates port forwards and outbound NAT
- ✅ **Static Routes** - Documents routing configuration
- ✅ **IPsec VPN** - Converts site-to-site VPN tunnels with detailed guides
- ✅ **Comprehensive Documentation** - Migration guides and checklists

## 📦 What's Included

- `pfsense_to_panos.py` - Main conversion script
- `sample_pfsense_config.xml` - Example pfSense configuration
- Generated Terraform files use **PAN-OS Provider v2.0.7** (latest)
- Comprehensive migration documentation

## 🚀 Quick Start

```bash
# 1. Export your pfSense configuration
#    pfSense WebUI → Diagnostics → Backup & Restore → Download

# 2. Run the converter
chmod +x pfsense_to_panos.py
./pfsense_to_panos.py your-config.xml

# 3. Review generated files
cd panos-terraform/
cat MIGRATION_GUIDE.txt

# 4. Configure Terraform
cat > terraform.tfvars << EOF
panos_hostname = "192.168.1.1"
panos_username = "admin"
panos_password = "your-password"
panos_insecure = true
vsys           = "vsys1"
EOF

# 5. Deploy to PAN-OS
terraform init
terraform plan
terraform apply
```

## 📋 Prerequisites

- **Python 3.7+** (uses only standard library)
- **Terraform 1.8+** 
- **Palo Alto Networks firewall** (target platform)
- **pfSense configuration XML** export
- **PAN-OS Provider v2.0+** (auto-downloaded by Terraform)

## 🔄 Migration Workflow

```
┌──────────────────┐
│  pfSense Config  │
│   (config.xml)   │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   Converter      │
│   pfsense_to_    │
│   panos.py       │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  PAN-OS TF Files │
│  • zones.tf      │
│  • security_     │
│    rules.tf      │
│  • nat_rules.tf  │
│  • addresses.tf  │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│  Review & Edit   │
│  • Zone mappings │
│  • Interfaces    │
│  • VPN PSKs      │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│ Terraform Apply  │
│ → PAN-OS Firewall│
└──────────────────┘
```

## 📊 Generated Terraform Files

| File | Description | Status |
|------|-------------|--------|
| `provider.tf` | PAN-OS provider v2.0+ configuration | Ready |
| `variables.tf` | Input variables for deployment | Ready |
| `zones.tf` | Security zones (trust, untrust, dmz, etc.) | Ready |
| `address_objects.tf` | Address objects from pfSense aliases | Ready |
| `address_groups.tf` | Address groups (multi-entry aliases) | Ready |
| `service_objects.tf` | Service objects for custom ports | Ready |
| `security_rules.tf` | Security policy (zone-based rules) | Needs review |
| `nat_rules.tf` | NAT policy (DNAT & SNAT) | Needs review |
| `interfaces.tf` | Interface mapping documentation | Reference |
| `static_routes.tf` | Static route documentation | Reference |
| `ipsec.tf` | IPsec VPN configuration | Needs PSKs |

## 🔧 Generated Documentation

### MIGRATION_GUIDE.txt
Complete migration documentation covering:
- Configuration summary and statistics
- Interface and zone mappings
- Step-by-step migration tasks
- Critical differences between pfSense and PAN-OS
- Pre-migration checklist
- Terraform deployment steps
- Post-migration tasks
- Known limitations
- Rollback plan

### VPN_MIGRATION_GUIDE.txt
VPN-specific migration guide including:
- IPsec tunnel parameters
- Phase 1 and Phase 2 configurations
- OpenVPN to GlobalProtect migration path
- Testing procedures
- Troubleshooting commands

## 🎯 Example: Complete Migration

### 1. Export pfSense Configuration

```bash
# From pfSense WebUI:
# Diagnostics → Backup & Restore → Download configuration as XML
```

### 2. Run Converter

```bash
python3 pfsense_to_panos.py pfsense-config.xml --output-dir my-panos-migration
```

Output:
```
Parsing pfSense configuration...

Parsing complete!
  System: firewall.example.com
  Interfaces: 4
  Zones (mapped): 4
  VLANs: 2
  Aliases: 5
  Firewall Rules: 9
  NAT Port Forwards: 3
  NAT Outbound: 3
  IPsec Tunnels: 2
  OpenVPN Servers: 1

Generating PAN-OS Terraform configuration...
  ✓ Generated provider.tf
  ✓ Generated zones.tf
  ✓ Generated address_objects.tf
  ✓ Generated security_rules.tf
  [... more files ...]

✓ Successfully generated PAN-OS Terraform configuration!
```

### 3. Review Generated Configuration

```bash
cd my-panos-migration/

# Read the migration guide first!
less MIGRATION_GUIDE.txt

# Review key files
cat zones.tf              # Check zone mappings
cat security_rules.tf     # Review security policy
cat nat_rules.tf          # Check NAT rules
```

### 4. Configure Authentication

```bash
# Create terraform.tfvars
cat > terraform.tfvars << EOF
panos_hostname = "10.0.0.1"       # Your PAN-OS firewall
panos_username = "admin"
panos_password = "YourPassword"
panos_insecure = true             # Self-signed certs
vsys           = "vsys1"
EOF
```

### 5. Update TODO Items

The generated files contain `# TODO:` comments for items requiring manual configuration:

```hcl
# security_rules.tf
destination_zones = ["any"]  # TODO: Set appropriate destination zone

# nat_rules.tf
interface = "ethernet1/1"  # TODO: Set correct interface

# ipsec.tf
pre_shared_key = "***CONFIGURE_PSK_HERE***"  # TODO: Add PSK
```

### 6. Initialize and Deploy

```bash
# Initialize Terraform
terraform init

# Preview changes
terraform plan

# Apply to TEST environment first!
terraform apply
```

### 7. Commit Changes in PAN-OS

```bash
# Via GUI: Commit → Commit
# Via CLI: commit
```

## ⚙️ Configuration Examples

### Generated Security Zone

```hcl
resource "panos_zone" "trust" {
  name = "trust"
  mode = "layer3"
  
  location = {
    vsys = {
      name = var.vsys
    }
  }
  
  # Interfaces from pfSense: lan
  # Note: Map these to actual PAN-OS interfaces
  # interfaces = ["ethernet1/1"]
}
```

### Generated Address Object

```hcl
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
```

### Generated Security Rule

```hcl
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
      name        = "Allow web servers to database"
      action      = "allow"
      description = "Allow web servers to database"
      source_zones = [panos_zone.dmz.name]
      source_addresses = ["WebServers"]
      destination_zones = ["any"]  # TODO: Update
      destination_addresses = ["DatabaseServers"]
      applications = ["application-default"]
      services = ["application-default"]
    },
  ]
}
```

### Generated NAT Rule

```hcl
resource "panos_nat_rule_group" "nat_rules" {
  rules = [
    {
      name = "HTTP to WebServer1"
      description = "HTTP to WebServer1"
      
      original_packet = {
        source_zones = [panos_zone.untrust.name]
        destination_zone = panos_zone.untrust.name
        source_addresses = ["any"]
        destination_addresses = ["any"]  # TODO: Set WAN IP
      }
      
      translated_packet = {
        source = {}
        destination = {
          static_translation = {
            address = "10.0.10.10"
            port = 80
          }
        }
      }
    },
  ]
}
```

## 🔍 Key Features

### Intelligent Zone Mapping

The converter automatically maps pfSense interfaces to PAN-OS security zones:

| pfSense Interface | PAN-OS Zone | Logic |
|-------------------|-------------|-------|
| wan | untrust | External/Internet-facing |
| lan | trust | Internal/trusted network |
| dmz | dmz | DMZ/semi-trusted |
| opt1 (DMZ) | dmz | Based on description |
| opt2 (Guest) | guest | Based on description |

### Address Object Conversion

pfSense aliases → PAN-OS address objects:

```
pfSense Alias:
  Name: WebServers
  Type: host
  Addresses: 10.0.10.10 10.0.10.11 10.0.10.12

Converts to:
  3 address objects: WebServers_0, WebServers_1, WebServers_2
  1 address group: WebServers (containing all 3)
```

### Rule Logic Preservation

pfSense rules → PAN-OS security rules with zone context:

```
pfSense Rule:
  Interface: dmz
  Action: pass
  Source: WebServers
  Destination: DatabaseServers
  Port: 3306

Converts to:
  Name: Allow web servers to database
  Action: allow
  Source Zone: dmz
  Source Address: WebServers
  Destination Zone: [TODO: Set based on DB location]
  Destination Address: DatabaseServers
  Service: tcp/3306
```

## ⚠️ Important Migration Notes

### 1. Zone-Based Security Model

**pfSense:** Interface-based rules (rules applied to interface)  
**PAN-OS:** Zone-based rules (rules between zones)

**Impact:** Every rule needs source AND destination zones defined.

### 2. Interface Mapping Required

pfSense uses descriptive names (wan, lan, opt1).  
PAN-OS uses numbered interfaces (ethernet1/1, ethernet1/2).

**Action:** Review `interfaces.tf` and update zone assignments with actual PAN-OS interfaces.

### 3. Application-ID vs Port-Based

**pfSense:** Traditional port-based filtering  
**PAN-OS:** Application-aware filtering (App-ID)

**Recommendation:** Leverage App-ID for better security by using `application-default` where possible.

### 4. VPN Authentication

All IPsec pre-shared keys are **redacted** for security.

**Action:** Review `VPN_MIGRATION_GUIDE.txt` and configure PSKs manually.

### 5. Manual Configuration Required

Some features require manual configuration:
- Interface assignments to zones
- VPN pre-shared keys
- Log forwarding profiles
- Security profiles (AV, IPS, URL filtering)
- DHCP services (not supported via Terraform)

## 🔒 Security Considerations

1. **Credentials**
   - Never commit `terraform.tfvars` to version control
   - Use environment variables or secure vaults
   - Rotate passwords after migration

2. **VPN Keys**
   - PSKs are redacted in generated files
   - Store securely (password manager, vault)
   - Document key-to-tunnel mappings

3. **Testing**
   - **ALWAYS** test in lab environment first
   - Validate all rules before production
   - Have rollback plan ready

## 📈 What Gets Migrated

| Feature | pfSense | PAN-OS | Status |
|---------|---------|--------|--------|
| Firewall Rules | Filter rules | Security policy | ✅ Converted |
| NAT Port Forwards | Port forward rules | Destination NAT | ✅ Converted |
| NAT Outbound | Outbound NAT | Source NAT | ✅ Converted |
| Address Aliases | Aliases (host/network) | Address objects | ✅ Converted |
| Service Aliases | Aliases (port) | Service objects | ✅ Converted |
| Zones | Interfaces | Security zones | ✅ Mapped |
| IPsec VPN | IPsec tunnels | IKE gateway + IPsec tunnel | ✅ Documented |
| OpenVPN | OpenVPN server/client | GlobalProtect | ⚠️ Manual |
| Static Routes | Routes | Static routes | 📝 Documented |
| DHCP | DHCP server | DHCP (GUI only) | ⚠️ Manual |
| Interfaces | Interface config | Layer3 interface | 📝 Reference |
| VLANs | VLAN config | VLAN interface | 📝 Reference |

**Legend:**
- ✅ Converted - Full Terraform resources generated
- 📝 Documented - Configuration documented for reference
- ⚠️ Manual - Requires manual configuration

## 🐛 Troubleshooting

### Issue: "Failed to parse XML"

**Solution:** Ensure XML is not encrypted. Decrypt if needed:
```bash
openssl enc -d -aes-256-cbc -in encrypted.xml -out config.xml
```

### Issue: "Terraform provider connection failed"

**Solution:**
1. Verify PAN-OS IP is accessible: `ping 192.168.1.1`
2. Check credentials in `terraform.tfvars`
3. Set `panos_insecure = true` for self-signed certs
4. Ensure PAN-OS management interface is accessible

### Issue: "Zone not found"

**Solution:** Review `zones.tf` and ensure zones are created before rules that reference them.

### Issue: "Invalid rule configuration"

**Solution:** Check TODO items in `security_rules.tf` - destination zones must be set.

## 📚 Additional Resources

- [PAN-OS Administrator's Guide](https://docs.paloaltonetworks.com)
- [Terraform PAN-OS Provider v2.0](https://registry.terraform.io/providers/PaloAltoNetworks/panos/latest)
- [PAN-OS Migration Best Practices](https://live.paloaltonetworks.com)
- [App-ID Database](https://applipedia.paloaltonetworks.com)

## 🎓 Migration Best Practices

1. **Lab Testing**
   - Deploy to test PAN-OS first
   - Validate all configurations
   - Test connectivity and policies

2. **Phased Approach**
   - Migrate zones first
   - Then addresses and services
   - Security rules next
   - NAT rules last
   - VPNs after basic connectivity

3. **Documentation**
   - Document interface mappings
   - Keep zone design documented
   - Maintain IP address inventory
   - Update network diagrams

4. **Validation**
   - Test each rule after migration
   - Verify NAT translations
   - Check VPN connectivity
   - Monitor logs for denies

5. **Optimization**
   - Use App-ID where possible
   - Apply security profiles
   - Configure log forwarding
   - Optimize rule order

## 🆚 pfSense vs PAN-OS Differences

| Aspect | pfSense | PAN-OS |
|--------|---------|--------|
| **Licensing** | Free & open source | Commercial (base + subscriptions) |
| **Rule Model** | Interface-based | Zone-based |
| **Filtering** | Port-based | Application-aware (App-ID) |
| **NAT** | Separate lists | Unified NAT policy |
| **IPS/AV** | Snort/Suricata packages | Integrated threat prevention |
| **VPN** | OpenVPN, IPsec | IPsec, GlobalProtect |
| **Management** | Single GUI | Panorama (centralized) available |
| **HA** | CARP | Active/Passive or Active/Active |

## 💡 Tips for Success

1. **Start Simple**
   - Begin with basic connectivity rules
   - Add complexity gradually
   - Test each phase

2. **Leverage App-ID**
   - Replace port-based rules with App-ID
   - Use application-default for services
   - Better security and visibility

3. **Use Security Profiles**
   - Enable threat prevention
   - Configure URL filtering
   - Apply antivirus scanning

4. **Monitor and Tune**
   - Review traffic logs
   - Identify application usage
   - Optimize policies based on actual traffic

5. **Documentation**
   - Keep migration notes
   - Document decisions
   - Update runbooks

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional pfSense feature support
- Enhanced zone mapping logic
- Better service object detection
- Additional documentation
- Bug fixes

## 📜 License

This tool is provided as-is for pfSense to PAN-OS migration. Use at your own risk and always test in a lab environment first.

## 🔗 Related Tools

Similar to the Panorama to Terraform converter, this follows the same reliable pattern:
1. Parse XML configuration
2. Extract configuration elements
3. Generate Terraform HCL
4. Provide migration documentation

## ⚡ Quick Reference

```bash
# Export from pfSense
Diagnostics → Backup & Restore → Download configuration

# Convert to PAN-OS Terraform
python3 pfsense_to_panos.py config.xml

# Review configuration
cd panos-terraform/
cat MIGRATION_GUIDE.txt
cat VPN_MIGRATION_GUIDE.txt

# Configure authentication
vim terraform.tfvars

# Deploy
terraform init
terraform plan
terraform apply

# Commit in PAN-OS
# GUI: Commit → Commit
# CLI: commit
```

---

**Made with ❤️ for Network Engineers migrating from pfSense to Palo Alto Networks**

**🔥 Perfect for platform upgrades, compliance requirements, and enterprise firewall deployments**
