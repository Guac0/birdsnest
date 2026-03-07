what needs to be done manually in drawio due to technical/practicality reasons:
1. add subnet names
2. add router details
3. add router interface details and space them properly
4. edit main textbox
5. disable page view
usage: `python tabula.py pathToCsv.csv maxHostsPerRow(int)`
output: network_diagram.drawio (import this into the drawio website)

breaks:
1. nonexistent module `import "drawpyo_utils"`
2. `entry = dict(zip(headers, row[1:5]))` should be `entry = dict(zip(headers, row[:5]))` - remove the 1
3. `page = drawpyo.Page()` should be `page = drawpyo.Page(file=file)`