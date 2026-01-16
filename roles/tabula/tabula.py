import drawpyo
#import drawpyo_utils
import csv
import ipaddress
import os
import sys
import math

def sort_ip(x):
    # Parse the address objects
    ip_obj = ipaddress.ip_address(x['ip'])
    subnet_obj = ipaddress.ip_network(x['subnet'])
    
    # Return a tuple where the first element is the version (4 or 6)
    # This prevents the TypeError by separating the address types first
    return (
        ip_obj.version,      # Sorts all IPv4 first, then all IPv6
        subnet_obj,          # Sorts by subnet
        ip_obj,              # Sorts by IP within that subnet
        x['os'].lower(),
        x['hostname'].lower()
    )

def parse_csv(file="input.csv"):
    hosts = []
    headers = ["subnet","ip","hostname","os","services"]
    headers_matches = [
        ["sub","net"],
        ["ip"],
        ["host","name"],
        ["os","operat"],
        ["service","scor","special","note"]
    ]
    with open(file, 'r') as file:
        reader = csv.reader(file, delimiter=',')
        # Parse each line and print or process the fields
        rowindex = 1
        for row in reader:
            # Ensure the row has the correct number of fields
            #print(f"len(row): {len(row)}, len(headers): {len(headers)}")
            if len(row) != 0:
                if len(row) < len(headers):
                    raise ValueError(f"Provided input file does not have enough columns on row {rowindex}!")
                if rowindex == 1:
                    for i in range(0,len(headers)):
                        condition=False
                        for match in headers_matches[i]:
                            if match in row[i].lower():
                                condition = True
                        if not condition:
                            print(f"Column {i} fails soft validity check, are you sure that your columns are set up correctly? Expected value relating to {headers[i]}")
                else:
                    # Create a dictionary for easier field access (optional)
                    entry = dict(zip(headers, row[:5]))
                    hosts.append(entry)
            rowindex += 1
    hosts.sort(key=sort_ip)
    return hosts

def get_os_string(full_os_str):
    full_os_str = full_os_str.lower()
    if "internet" in full_os_str:
        #return "https://symbols.getvecta.com/stencil_62/4_cloud.377dbc86e9.jpg"
        #return "https://cdn-icons-png.freepik.com/256/6767/6767238.png?semt=ais_white_label" #lines
        #return "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcS6Lu2YFMt90ZOe8MeBYiVhvE1VCi7xYQdY1g&s"
        return "https://static.wikia.nocookie.net/cloudss/images/9/94/The_Clouds_Wiki_Icon.png"
    if "router" in full_os_str:
        return "https://symbols.getvecta.com/stencil_240/204_router.7b208c1133.png"
    if "windows server" in full_os_str:
        return "https://upload.wikimedia.org/wikipedia/commons/thumb/8/87/Windows_logo_-_2021.svg/960px-Windows_logo_-_2021.svg.png?20220927154043"
    if "windows" in full_os_str:
        return "https://upload.wikimedia.org/wikipedia/commons/thumb/4/48/Windows_logo_-_2012_%28dark_blue%29.svg/250px-Windows_logo_-_2012_%28dark_blue%29.svg.png"
        #return "https://upload.wikimedia.org/wikipedia/commons/thumb/4/48/Windows_logo_-_2012_%28dark_blue%29.svg/1024px-Windows_logo_-_2012_%28dark_blue%29.svg.png"
    if "ubuntu" in full_os_str:
        # no text:
        return "https://upload.wikimedia.org/wikipedia/commons/thumb/9/9e/UbuntuCoF.svg/1200px-UbuntuCoF.svg.png"
    if "fedora" in full_os_str:
        # no text:
        return "https://upload.wikimedia.org/wikipedia/commons/thumb/4/41/Fedora_icon_%282021%29.svg/1280px-Fedora_icon_%282021%29.svg.png"
    if "debian" in full_os_str:
        # text:
        #return "https://upload.wikimedia.org/wikipedia/commons/thumb/4/4a/Debian-OpenLogo.svg/640px-Debian-OpenLogo.svg.png"
        # no text:
        return "https://upload.wikimedia.org/wikipedia/commons/thumb/6/66/Openlogo-debianV2.svg/640px-Openlogo-debianV2.svg.png"
    if "alpine" in full_os_str:
        # text:
        #return "https://upload.wikimedia.org/wikipedia/commons/thumb/6/60/New_Logo_Alpine_Linux.svg/640px-New_Logo_Alpine_Linux.svg.png"
        # no text:
        #return "https://upload.wikimedia.org/wikipedia/commons/2/2c/Alpine_Linux_logo.png?20150706141851"
        # transparent:
        return "https://distrosea.com/distro-icons/alpine.svg"
    if "rocky" in full_os_str:
        # text:
        #return "https://samba.plus/fileadmin/_processed_/0/8/csm_Rocky_Linux_97c0115185.png"
        # no text:
        return "https://upload.wikimedia.org/wikipedia/commons/7/77/Rocky_Linux_logo.svg"
    if "centos" in full_os_str:
        return "https://commons.wikimedia.org/wiki/File:CentOS_color_logo.svg"
    if "rhel" in full_os_str:
        return "https://upload.wikimedia.org/wikipedia/commons/thumb/d/d8/Red_Hat_logo.svg/960px-Red_Hat_logo.svg.png"
    if "amazon" in full_os_str:
        # too small:
        #return "https://miro.medium.com/v2/resize:fit:640/format:webp/1*WzXKURvs7JRfRKtO-xskgw.png"
        # text:
        #return "https://encrypted-tbn0.gstatic.com/images?q=tbn:ANd9GcR8WeEeItEdbZe1SaJPalHrs_LrUaWNkN0ENQ&s"
        return "https://icon2.cleanpng.com/20180817/vog/8968d0640f2c4053333ce7334314ef83.webp"
    if "suse" in full_os_str:
        # text:
        #return "https://upload.wikimedia.org/wikipedia/commons/thumb/d/d0/OpenSUSE_Logo.svg/1200px-OpenSUSE_Logo.svg.png"
        # no text:
        return "https://upload.wikimedia.org/wikipedia/commons/thumb/d/d1/OpenSUSE_Button.svg/640px-OpenSUSE_Button.svg.png"
    if "solaris" in full_os_str:
        return "https://upload.wikimedia.org/wikipedia/commons/thumb/2/25/Solaris_9_logo.svg/960px-Solaris_9_logo.svg.png"
    return "https://symbols.getvecta.com/stencil_240/79_fileserver.c500813aaa.png"

def draw_main(hosts,file_path,file_name,max_host_per_row = 4):
    # Draw Setup
    #custom_library = drawpyo.diagram.import_shape_database(
    #    file_name='os.toml'
    #)
    file = drawpyo.File()
    file.file_path = file_path
    file.file_name = file_name
    page = drawpyo.Page("""file=file""")
        #width=100, # will auto expand
        #height=100
    #)
    page.grid = 0
    #page.page_view = 0 # doesnt work
    page.background = "#ffffff"

    text = drawpyo.diagram.text_format.TextFormat(
        fontColor='#000000',
        fontFamily='Helvetica', # go to helvetica, spiderman!
        fontSize=10,
        align='center',
        direction='horizontal',
        labelPosition='center',
        # labelBackgroundColor='#ff2d00',
        #verticalAlign='bottom',
        #spacingBottom=-15
    )
    texttitle = drawpyo.diagram.text_format.TextFormat(
        fontColor='#000000',
        fontFamily='Helvetica',
        fontSize=16,
        align='center',
        direction='horizontal',
        labelPosition='center',
        bold=1
        # labelBackgroundColor='#ff2d00',
        #verticalAlign='bottom',
        #spacingBottom=-15
    )
    textrouter = drawpyo.diagram.text_format.TextFormat(
        fontColor='#000000',
        fontFamily='Helvetica',
        fontSize=10,
        align='center',
        direction='horizontal',
        labelPosition='center',
        # labelBackgroundColor='#ff2d00',
        verticalAlign='bottom',
        spacingBottom=45
    )
    textinternet = drawpyo.diagram.text_format.TextFormat(
        fontColor='#000000',
        fontFamily='Helvetica',
        fontSize=10,
        align='center',
        direction='horizontal',
        labelPosition='center',
        # labelBackgroundColor='#ff2d00',
        verticalAlign='bottom',
        spacingBottom=60
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
    colors = [
        #[strokeColor,fillColor,fontColor]
        ["#2D8A5B", "#F0F9F4", "#144D3E"], # Green
        ["#7B61FF", "#F2F0FF", "#4A3BB1"], # Purple
        ["#D97706", "#FFFBEB", "#92400E"], # Amber
        ["#00A4A6", "#E6F6F7", "#147EBA"], # Blue
        ["#E11D48", "#FFF1F2", "#9F1239"], # Red
        ["#4B5563", "#F3F4F6", "#1F2937"]  # Grey
    ]
    color_index = 0
    image_size = 75
    host_spacing = image_size + 50
    center_spacing = 50

    #full_style = ";".join(style_tags) + ";"
    parent_container_width = (50*2)+((host_spacing)*max_host_per_row)
    textobj = drawpyo.diagram.Object(
        text_format=texttitle,
        value=f'Company<br/>Location<br/>FQDN',
        page=page,
        width=image_size,
        height=image_size,
        position=(parent_container_width+center_spacing,20),
        html=1,
        whiteSpace="nowrap",
        image=""
    )
    text_style = (
        "text;"
        "html=1;"
        "strokeColor=none;"
        "fillColor=none;"
        #"align=center;"
        #"verticalAlign=middle;"
        "whiteSpace=nowrap;"
    )
    textobj.apply_style_string(text_style)
    textobj.text_format = texttitle
    router = drawpyo.diagram.Object(
        value=f'Router<br/>127.0.0.1<br/>PfSense',
        page=page,
        width=image_size,
        height=image_size,
        position=(parent_container_width+center_spacing,140)
    )
    router.text_format = textrouter
    stylestring = (
        "shape=image;"
        "verticalLabelPosition=bottom;"
        "verticalAlign=top;"
        "imageAspect=0;"
        "aspect=fixed;"
        "html=1;"
        "whiteSpace=nowrap;"
        f"image={get_os_string('router')};"
    )
    router.apply_style_string(stylestring)
    internet = drawpyo.diagram.Object(
        value=f'Public Internet',
        page=page,
        width=image_size,
        height=image_size,
        position=(parent_container_width+center_spacing,330)
    )
    stylestring = (
        "shape=image;"
        "verticalLabelPosition=bottom;"
        "verticalAlign=top;"
        "imageAspect=0;"
        "aspect=fixed;"
        "html=1;"
        "whiteSpace=nowrap;"
        f"image={get_os_string('internet')};"
    )
    internet.apply_style_string(stylestring)
    internet.text_format = textinternet
    drawnSubnets = []
    num_subnets = len(subnets)
    col_y_starts = [0, 0]

    total_rows = 0
    row_counts = []
    for s_name in subnets:
        # math.ceil ensures 9 hosts / 4 per row = 3 rows
        count = math.ceil(len(subnets[s_name]) / max_host_per_row)
        row_counts.append(count)
        total_rows += count
    half_rows = total_rows / 2
    cumulative_rows = 0
    split_index = 0
    #use_two_columns = num_subnets > 2
    use_two_columns = total_rows > 3

    # Find the index where we cross the 50% threshold
    for i, count in enumerate(row_counts):
        cumulative_rows += count
        split_index = i
        if cumulative_rows >= half_rows:
            break
    current_subnet_idx = 0
    
    current_subnet_idx = 0
    for subnet in subnets:
        #print(subnet)
        drawnHosts = []
        for host in subnets[subnet]:
            item = drawpyo.diagram.Object(
                value=f'{host["hostname"]}<br/>{host["ip"]}<br/>{host["os"]}<br/>{host["services"]}', #\n for new line
                page=page,
                width=image_size,
                height=image_size
            )
            stylestring = (
                "shape=image;"
                "verticalLabelPosition=bottom;"
                "verticalAlign=top;"
                "imageAspect=0;"
                "aspect=fixed;"
                "html=1;"
                "whiteSpace=nowrap;"
                f"image={get_os_string(host["os"])};"
            )
            item.apply_style_string(stylestring)
            item.text_format = text
            drawnHosts.append(item)

        # must create parent container after icons in order to preserve position
        parent_container = drawpyo.diagram.Object(
            page=page,
            value=f"{subnet}",
            autosize_margin=50
        )
        parent_container.apply_style_string(
            f"html=1;fontSize=12;fontStyle=0;shape=mxgraph.aws4.group;grIcon=mxgraph.aws4.group_security_group;grStroke=0;strokeColor={colors[color_index][0]};fillColor={colors[color_index][1]};verticalAlign=top;align=left;spacingLeft=30;fontColor={colors[color_index][2]};dashed=0;"
        )
        color_index += 1
        if color_index >= len(colors):
            color_index = 0
        row_index, col_index = 0, 0
        for index,item in enumerate(drawnHosts,start=1):
            if col_index > max_host_per_row - 1:
                col_index = 0
                row_index += 1
            parent_container.add_object(item)
            item.position_rel_to_parent = ((col_index * host_spacing), (row_index * (host_spacing * 1.25)))
            # 4 items: (30, 0) (150, 0) (30, 100) (150, 100)
            col_index += 1
        parent_container.resize_to_children()
        connection = drawpyo.diagram.edges.Edge(
            page=page,
            source=parent_container,
            target=router,
            label="127.0.0.1",
            label_position=-1,
            label_offset=15,
            endSize=40,
            startSize=40,
            rounded=True,
            waypoints="vertical", #orthogonal
            connection="link" #line
        )
        #parent_container.position = (0, container_y_start)
        parent_container.height += 25 # text spacing
        if use_two_columns:
            # Subnets up to and including the split_index go left
            current_col = 0 if current_subnet_idx <= split_index else 1
            
            if current_col == 1:
                connection.apply_style_string("label_offset=-15;")
            
            x_pos = current_col * (parent_container_width + (center_spacing*3) + image_size)
            parent_container.position = (x_pos, col_y_starts[current_col])
            col_y_starts[current_col] += parent_container.height + 50
        else:
            parent_container.position = (0, col_y_starts[0])
            col_y_starts[0] += parent_container.height + 50
        current_subnet_idx += 1

        #container_y_start += parent_container.height + 30
        drawnSubnets.append(parent_container)
    
    connection = drawpyo.diagram.edges.Edge(
        page=page,
        source=internet,
        target=router,
        #label="test",
        #label_position=-1,
        #label_offset=25,
        endSize=30,
        startSize=30,
        rounded=True,
        targetPerimeterSpacing=33,
        waypoints="vertical", #orthogonal
        connection="link" #line
    )

    file.write()
          
def main():
    if len(sys.argv) > 1:
        input_file = sys.argv[1]
    else:
        input_file = "input.csv"
    if len(sys.argv) > 2:
        max_host_per_row = int(sys.argv[2])
    else:
        max_host_per_row = 4
    
    file_path = os.getcwd()
    file_name = "network_diagram.drawio"

    print("Parsing input file...")
    hosts = parse_csv(input_file)
    print("Parsed and sorted hosts.")
    print("Drawing diagram...")
    draw_main(hosts,file_path,file_name,max_host_per_row)
    print(f"Diagram generated at {file_path}{file_name}")

main()