# import xml.etree.ElementTree as ET
import xml.dom.minidom as minidom

# Variables related to file handling
input_file = "config.xml"
output_file = "new_config.xml"

# Read XML content from the input file
with open(input_file, "r") as file:
    xml_content = file.read()

doc = minidom.parseString(xml_content)

# Function to get the value of an element by tag name and index
def get_element_value(element, tag_name, index=0):
    elements = element.getElementsByTagName(tag_name)
    if elements:
        return elements[index].firstChild.nodeValue
    return None

# Function to modify the value of an element by tag name and index
def modify_element_value(element, tag_name, new_value, index=0):
    elements = element.getElementsByTagName(tag_name)
    if elements:
        elements[index].firstChild.nodeValue = new_value

# Extracting hostname and domain values out of the system tree
#system_elements = doc.getElementsByTagName("system")
#for element in system_elements:
#    hostname = get_element_value(element, "hostname")
#    domain = get_element_value(element, "domain")

# Extracting defined interface network elements such as IP address and gateway for both IPv4 and IPv6
target_interface = "wan"


# Commit changes - Write the serialized XML to an external file
def saveFile():
    modified_xml = doc.toprettyxml(indent="", newl="")
    modified_xml_with_line_break = modified_xml.replace('<pfsense>', '\n<pfsense>', 1)
    with open(output_file, "w") as file:
        file.write(modified_xml_with_line_break)



def showIp():

# Find the value of ipaddr, ipaddrv6, subnet and subnetv6 inside of interfaces tree
    interfaces_elements = doc.getElementsByTagName("interfaces")
    for interfaces_element in interfaces_elements:
        wan_elements = interfaces_element.getElementsByTagName(target_interface)
        for wan_element in wan_elements:
            wan_ipaddress_v4 = get_element_value(wan_element, "ipaddr")
            wan_ipaddress_v6 = get_element_value(wan_element, "ipaddrv6")
            wan_subnet_v4 = get_element_value(wan_element, "subnet")
            wan_subnet_v6 = get_element_value(wan_element, "subnetv6")

# Find the value of gateway where ipprotocol and interface are defined
    gateway_items = doc.getElementsByTagName("gateway_item")
    for gateway_item in gateway_items:
        interface = gateway_item.getElementsByTagName("interface")[0].firstChild.nodeValue
        ipprotocol = gateway_item.getElementsByTagName("ipprotocol")[0].firstChild.nodeValue
        if interface == "wan" and ipprotocol == "inet":
            wan_gateway_v4 = get_element_value(gateway_item, "gateway")
        if interface == "wan" and ipprotocol == "inet6":
            wan_gateway_v6 = get_element_value(gateway_item, "gateway")

    print("\n== WAN interface ==")
    if wan_ipaddress_v4 is not None:
            print("{} - IPv4: {}/{}".format(target_interface, wan_ipaddress_v4, wan_subnet_v4))
    else:
            print("No IPv4 found for {}.".format(target_interface))

    if wan_ipaddress_v6 is not None:
            print("{} - IPv6: {}/{}".format(target_interface, wan_ipaddress_v6, wan_subnet_v6))
    else:
            print("No IPv6 found for {}.".format(target_interface))

    changeIp(interfaces_elements)


def changeIp(interfaces_elements):
    if input("\nDo you want to change the IPv4 for the WAN interface (y/n)? ") == 'y':
            wan_ipaddress_v4 = input("Please enter a new IPv4: ")
            wan_subnet_v4 = input("Please enter a v4 subnet mask: ")
            for interfaces_element in interfaces_elements:
                wan_elements = interfaces_element.getElementsByTagName("wan")
                for wan_element in wan_elements:
                    modify_element_value(wan_element, "ipaddr", wan_ipaddress_v4)
                    modify_element_value(wan_element, "subnet", wan_subnet_v4)
            print("Changing WAN IPv4... OK")

    else:
            print("bye")

    if input("\nDo you want to change the IPv6 for the WAN interface (y/n)? ") == 'y':
            wan_ipaddress_v6 = input("Please enter a new IPv6: ")
            wan_subnet_v6 = input("Please enter a v6 subnet mask: ")
            for interfaces_element in interfaces_elements:
                wan_elements = interfaces_element.getElementsByTagName("wan")
                for wan_element in wan_elements:
                    modify_element_value(wan_element, "ipaddrv6", wan_ipaddress_v6)
                    modify_element_value(wan_element, "subnetv6", wan_subnet_v6)
            print("Changing WAN IPv6... OK")

    else:
            print("bye")
    # Passing variable so we can use it as routerid in FRR package
    disablePackageFrr(wan_ipaddress_v4)

def showInterfaces():

    if input("\nWould you like to delete all available interfaces except for WAN? This will delete relevant firewall rules, gateways, and NAT outbound rules (y/n): ") == 'y':
        cleanInterfaces()
        cleanGateways()
        cleanFirewallRules()
        cleanNatOutbound()
    else:
        print("bye")


def showHostname():
    print("== FQDN ==")
#	hostname_element = root.find("system/hostname")
#	domain_element = root.find("system/domain")
# Extracting hostname and domain values out of the system tree
    system_elements = doc.getElementsByTagName("system")
    for element in system_elements:
        hostname = get_element_value(element, "hostname")
        domain = get_element_value(element, "domain")

    print("Hostname: {} - Domain: {}".format(hostname, domain))

    if input("\nWould you like to change the hostname (without the domain part)? (y/n): ") == 'y':
        changeHostname(system_elements, hostname, domain)
    else:
        print("bye")


def showTunnels():
    print("\n== WireGuard tunnels ==")
    # Initial amount of tunnels
    tunnels_number = 0

    installedpackages_elements = doc.getElementsByTagName("installedpackages")
    for installedpackages_element in installedpackages_elements:
        wireguard_elements = installedpackages_element.getElementsByTagName("wireguard")
        if wireguard_elements is not None:
            for wireguard_element in wireguard_elements:
                tunnels_elements = wireguard_element.getElementsByTagName("tunnels")
                for tunnels_element in tunnels_elements:
                    item_elements = tunnels_element.getElementsByTagName("item")
                    for item_element in item_elements:
                        tunnel_name = get_element_value(item_element, "name")
                        print(tunnel_name)
                        tunnels_number += 1
    print("Tunnels: {}". format(tunnels_number))

    if input("Would you like to delete all WireGuard tunnels? (y/n): ") == 'y':
        cleanTunnels(installedpackages_elements)
    else:
        print("bye")


def cleanTunnels(installedpackages_elements):
    installedpackages_elements = doc.getElementsByTagName("installedpackages")
    for installedpackages_element in installedpackages_elements:
        wireguard_elements = installedpackages_element.getElementsByTagName("wireguard")
        if wireguard_elements is not None:
            for wireguard_element in wireguard_elements:
                tunnels_elements = wireguard_element.getElementsByTagName("tunnels")
                peers_elements = wireguard_element.getElementsByTagName("peers")
                for tunnels_element in tunnels_elements:
                    item_elements = tunnels_element.getElementsByTagName("item")
                    for item_element in item_elements:
                        parent = item_element.parentNode
                        parent.removeChild(item_element)
                for peers_element in peers_elements:
                    item_elements = peers_element.getElementsByTagName("item")
                    for item_element in item_elements:
                        parent = item_element.parentNode
                        parent.removeChild(item_element)
    print("Cleaning WireGuard tunnels... OK")



def changeHostname(system_elements, hostname, domain):
    new_hostname = input("\nEnter new hostname: ")

    for system_element in system_elements:
        modify_element_value(system_element, "hostname", new_hostname)
    print("Changing hostname... OK")

    installedpackages_elements = doc.getElementsByTagName("installedpackages")
    for installedpackages_element in installedpackages_elements:
        acme_elements = installedpackages_element.getElementsByTagName("acme")
        if acme_elements is not None:
            if input("\nAcme package has been detected. Would you like to change the hostname as well, for the SSL certificate? Please note this will not issue a new certificate (y/n):  ") == 'y':
                for acme_element in acme_elements:
                    domain_name_elements = doc.getElementsByTagName("a_domainlist")
                    for domain_name_element in domain_name_elements:
                        item_elements = domain_name_element.getElementsByTagName("item")
                        for item_element in item_elements:
                            fqdn = get_element_value(item_element, "name")
                            if fqdn == hostname + "." + domain:
                                modify_element_value(item_element, "name", new_hostname + "." + domain)
                                print("Changing the FQDN in Acme... OK")
                            else:
                                print("FQDN in Acme package does not match the one in General Setup.")
            else:
                print("Acme is not installed.")

    saveFile()

        

def showVirtualIps():
    print("\n== Virtual IPs ==")
    virtualip_elements = doc.getElementsByTagName("virtualip")
    for virtualip_element in virtualip_elements:
        vip_elements = doc.getElementsByTagName("vip")
        for vip_element in vip_elements:
            vip = get_element_value (vip_element, "subnet")
            print(vip)

    if input("Would you like to delete all Virtual IPs? (y/n): ") == 'y':
        cleanVirtualIps(vip_elements)
    else:
        print("bye")


def cleanInterfaces(): 

# Find the <virtualip> element
    interfaces_element = doc.getElementsByTagName("interfaces")[0]

# Get a list of all child elements
    interfaces_name_elements = interfaces_element.childNodes

# Iterate through child elements in reverse order and remove those not equal to "wan"
    for interfaces_name_element in reversed(interfaces_name_elements):
        if interfaces_name_element.nodeName != "wan":
            interfaces_element.removeChild(interfaces_name_element)

    print("Cleaning interfaces... OK")


def cleanVirtualIps(vip_elements):

    for vip_element in vip_elements:
        parent = vip_element.parentNode
        parent.removeChild(vip_element)

    print("Cleaning Virtual IPs... OK")



def cleanGateways():
    print("\n== Gateways ==")

# Find the value of gateway where ipprotocol and interface are defined
    gateway_items = doc.getElementsByTagName("gateway_item")
    for gateway_item in gateway_items:
        interface = gateway_item.getElementsByTagName("interface")[0].firstChild.nodeValue
        ipprotocol = gateway_item.getElementsByTagName("ipprotocol")[0].firstChild.nodeValue
        if interface == "wan" and ipprotocol == "inet":
            wan_gateway_v4 = get_element_value(gateway_item, "gateway")
        if interface != "wan":
                parent = gateway_item.parentNode
                parent.removeChild(gateway_item)
        if interface == "wan" and ipprotocol == "inet6":
            wan_gateway_v6 = get_element_value(gateway_item, "gateway")

    if input("{} - IPv4 Gateway: {}. Would you like to modify it? (y/n): ".format(target_interface, wan_gateway_v4)) == 'y':
        wan_gateway_v4 = input("Please enter new IPv4 gateway: ")
        for gateway_item in gateway_items:
            interface = gateway_item.getElementsByTagName("interface")[0].firstChild.nodeValue
            ipprotocol = gateway_item.getElementsByTagName("ipprotocol")[0].firstChild.nodeValue
            if interface == "wan" and ipprotocol == "inet":
                modify_element_value(gateway_item, "gateway", wan_gateway_v4)
        print("Changing IPv4 Gateway... OK")


    if input("{} - IPv6 Gateway: {}. Would you like to modify it? (y/n): ".format(target_interface, wan_gateway_v6)) == 'y':
        wan_gateway_v6 = input("Please enter new IPv4 gateway: ")
        for gateway_item in gateway_items:
            interface = gateway_item.getElementsByTagName("interface")[0].firstChild.nodeValue
            ipprotocol = gateway_item.getElementsByTagName("ipprotocol")[0].firstChild.nodeValue
            if interface == "wan" and ipprotocol == "inet6":
                modify_element_value(gateway_item, "gateway", wan_gateway_v6)
        print("Changing IPv6 Gateway... OK")

def cleanFirewallRules():

# Find the value of gateway where ipprotocol and interface are defined
    filter_items = doc.getElementsByTagName("filter")
    for filter_item in filter_items:
        rule_items = filter_item.getElementsByTagName("rule")
        for rule_item in rule_items:
            interface = rule_item.getElementsByTagName("interface")[0].firstChild.nodeValue
            if interface != "wan":
                parent = rule_item.parentNode
                parent.removeChild(rule_item)

    print("Cleaning firewall rules... OK")

def cleanNatOutbound():

    networks_to_keep = ["127.0.0.0/8", "::1/128"]

    nat_items = doc.getElementsByTagName("nat")
    for nat_item in nat_items:
        outbound_items = nat_item.getElementsByTagName("outbound")
        for outbound_item in outbound_items:
            rule_items = outbound_item.getElementsByTagName("rule")
            for rule_item in rule_items:
                network_element = rule_item.getElementsByTagName("network")[0]
                if network_element.firstChild.nodeValue not in networks_to_keep:
                    parent = rule_item.parentNode
                    parent.removeChild(rule_item)

    print("Cleaning NAT Outbound rules... OK")



def disablePackageFrr(arg):
    print("\n== FRR Package ==")

    installedpackages_elements = doc.getElementsByTagName("installedpackages")
    for installedpackages_element in installedpackages_elements:
        frrbgp_element = installedpackages_element.getElementsByTagName("frrbgp")[0]
        if frrbgp_element is not None:
            modify_element_value(frrbgp_element, "enable", "off")
            print("Disabling frrbgp... OK")
            modify_element_value(frrbgp_element, "routerid", arg)
            print("Changing routerid value to current WAN IPv4 address... OK")

        frr_element = installedpackages_element.getElementsByTagName("frr")[0]
        if frr_element is not None:
            modify_element_value(frr_element, "enable", "off")
            print("Disabling frr... OK")


showHostname()
showIp()
showInterfaces()
showVirtualIps()
showTunnels()
saveFile()
