import drawpyo
import csv
import ipaddress
import os
import math
import sys

def parse_csv(file="input.csv"):
    hosts = []
    headers = ["subnet","ip","hostname","os","services"]
    with open(file, 'r') as file:
        reader = csv.reader(file, delimiter=',')
        # Parse each line and print or process the fields
        firsttime = 0
        for row in reader:
            # Ensure the row has the correct number of fields
            #print(f"len(row): {len(row)}, len(headers): {len(headers)}")
            if len(row) == len(headers):
                if firsttime == 0:
                    firsttime = 1
                else:
                    # Create a dictionary for easier field access (optional)
                    entry = dict(zip(headers, row))
                    hosts.append(entry)
            else:
                print(f"Unexpected row count on row: {row}")
    hosts.sort(key=lambda x: (
        ipaddress.ip_network(x['subnet']),
        ipaddress.ip_address(x['ip']),
        x['os'].lower(),
        x['hostname'].lower()
    ))
    return hosts

def get_os_string(full_os_str):
    if "windows server" in full_os_str:
        return "windows_server"
    if "windows" in full_os_str:
        return "windows_client"
    if "ubuntu" in full_os_str:
        return "ubuntu"
    if "fedora" in full_os_str:
        return "fedora"
    if "debian" in full_os_str:
        return "debian"
    if "alpine" in full_os_str:
        return "alpine"
    if "rhel" in full_os_str:
        return "rhel"
    if "amazon" in full_os_str:
        return "amazon_linux"
    if "suse" in full_os_str:
        return "open_suse"
    return "unknown"

def draw_main(hosts,file_path,file_name):
    # Draw Setup
    custom_library = drawpyo.diagram.import_shape_database(
        file_name='os.toml'
    )
    file = drawpyo.File()
    file.file_path = file_path
    file.file_name = file_name
    page = drawpyo.Page(
        file=file,
        width=1100,
        height=850
    )

    # Constants for Layout
    HOST_WIDTH = 80
    HOST_HEIGHT = 80
    HORIZONTAL_SPACING = 40
    VERTICAL_SPACING = 60
    MAX_COLS = 5
    CONTAINER_PADDING = 50
    SUBNET_GAP = 100

    text = drawpyo.diagram.text_format.TextFormat(
        fontColor='#000000',
        fontFamily='Helvetica',
        fontSize=12,
        align='center',
        direction='horizontal',
        labelPosition='center',
        # labelBackgroundColor='#ff2d00',
        verticalAlign='bottom',
        spacingBottom=-35
    )

    # Organize the data
    # Note that the hosts array is already sorted, this just makes it easier
    subnets = {}
    for host in hosts:
        s = host["subnet"]
        if s not in subnets:
            subnets[s] = []
        subnets[s].append(host)

    # Now actually handle the data
    """
    last_subnet = ""
    host_iter = -1
    subnet_iter = -1
    for host in hosts:
        host_iter += 1
        if host["subnet"] != last_subnet:
            subnet_iter += 1
            host_iter = 0
            last_subnet = host["subnet"]
            # get size of box
            total_subnet_hosts = 0
            for host in hosts:
                if host["subnet"] == last_subnet:
                    total_subnet_hosts += 1
            # draw box
            # draw text
        # draw host at appropriate position in subnet box
    """
    host_spacing = 100
    max_host_per_row = 5
    container_y_start = 0
    colors = [
        #[strokeColor,fillColor]
        ["#00A4A6"],
        []
    ]

    print(subnets)
    for subnet in subnets:
        print(subnet)
        drawnHosts = []
        for host in subnets[subnet]:
            item = drawpyo.diagram.object_from_library(
                library=custom_library,
                obj_name=get_os_string(host["os"]),
                text_format=text,
                value=f'{host["hostname"]}\n{host["ip"]}\n{host["os"]}\n{host["services"]}', #\n for new line
                page=page,
                width=100,
                height=50
            )
            drawnHosts.append(item)

        # must create parent container after icons in order to preserve position
        parent_container = drawpyo.diagram.Object(
            page=page,
            value=subnet,
            autosize_margin=50
        )
        parent_container.apply_style_string(
            f"whiteSpace=wrap;fontSize=12;fontStyle=0;shape=mxgraph.aws4.group;grIcon=mxgraph.aws4.group_security_group;grStroke=0;strokeColor={colors[colorIndex][0]};fillColor=#E6F6F7;verticalAlign=top;align=left;spacingLeft=30;fontColor=#147EBA;dashed=0;"
        )
        row_index, col_index = 0, 0
        for index,item in enumerate(drawnHosts,start=1):
            parent_container.add_object(item)
            item.position_rel_to_parent = ((col_index * host_spacing), (row_index * host_spacing))
            # 4 items: (30, 0) (150, 0) (30, 100) (150, 100)
            col_index += 1
            if col_index > max_host_per_row - 1:
                col_index = 0
                row_index += 1
        parent_container.resize_to_children()
        #parent_container.position = (50, 65)
        parent_container.position = (0, container_y_start)
        container_y_start += (row_index+1)*200

    file.write()
          
def main():
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    else:
        input_file = "input.csv"
    file_path = os.getcwd()
    file_name = "network_diagram.drawio"

    print("Parsing input file...")
    hosts = parse_csv(input_file)
    print("Parsed and sorted hosts.")
    print("Drawing diagram...")
    draw_main(hosts,file_path,file_name)
    print(f"Diagram generated at {file_path}{file_name}")

main()