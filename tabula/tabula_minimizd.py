_H='router'
_G='internet'
_F='services'
_E='input.csv'
_D='hostname'
_C='subnet'
_B='ip'
_A='os'
import drawpyo,csv,ipaddress,os,sys,math
def sort_ip(x):A=ipaddress.ip_address(x[_B]);B=ipaddress.ip_network(x[_C]);return A.version,B,A,x[_A].lower(),x[_D].lower()
def parse_csv(file=_E):
	D=file;E=[];A=[_C,_B,_D,_A,_F];H=[['sub','net'],[_B],['host','name'],[_A,'operat'],['service','scor','special','note']]
	with open(D,'r')as D:
		I=csv.reader(D,delimiter=',');F=1
		for B in I:
			if len(B)!=0:
				if len(B)<len(A):raise ValueError(f"Provided input file does not have enough columns on row {F}!")
				if F==1:
					for C in range(0,len(A)):
						G=False
						for J in H[C]:
							if J in B[C].lower():G=True
						if not G:print(f"Column {C} fails soft validity check, are you sure that your columns are set up correctly? Expected value relating to {A[C]}")
				else:K=dict(zip(A,B[:5]));E.append(K)
			F+=1
	E.sort(key=sort_ip);return E
def get_os_string(full_os_str):
	A=full_os_str;A=A.lower()
	if _G in A:return'https://static.wikia.nocookie.net/cloudss/images/9/94/The_Clouds_Wiki_Icon.png'
	if _H in A:return'https://symbols.getvecta.com/stencil_240/204_router.7b208c1133.png'
	if'windows server'in A:return'https://upload.wikimedia.org/wikipedia/commons/thumb/8/87/Windows_logo_-_2021.svg/960px-Windows_logo_-_2021.svg.png?20220927154043'
	if'windows'in A:return'https://upload.wikimedia.org/wikipedia/commons/thumb/4/48/Windows_logo_-_2012_%28dark_blue%29.svg/250px-Windows_logo_-_2012_%28dark_blue%29.svg.png'
	if'ubuntu'in A:return'https://upload.wikimedia.org/wikipedia/commons/thumb/9/9e/UbuntuCoF.svg/1200px-UbuntuCoF.svg.png'
	if'fedora'in A:return'https://upload.wikimedia.org/wikipedia/commons/thumb/4/41/Fedora_icon_%282021%29.svg/1280px-Fedora_icon_%282021%29.svg.png'
	if'debian'in A:return'https://upload.wikimedia.org/wikipedia/commons/thumb/6/66/Openlogo-debianV2.svg/640px-Openlogo-debianV2.svg.png'
	if'alpine'in A:return'https://distrosea.com/distro-icons/alpine.svg'
	if'rocky'in A:return'https://upload.wikimedia.org/wikipedia/commons/7/77/Rocky_Linux_logo.svg'
	if'centos'in A:return'https://commons.wikimedia.org/wiki/File:CentOS_color_logo.svg'
	if'rhel'in A:return'https://upload.wikimedia.org/wikipedia/commons/thumb/d/d8/Red_Hat_logo.svg/960px-Red_Hat_logo.svg.png'
	if'amazon'in A:return'https://icon2.cleanpng.com/20180817/vog/8968d0640f2c4053333ce7334314ef83.webp'
	if'suse'in A:return'https://upload.wikimedia.org/wikipedia/commons/thumb/d/d1/OpenSUSE_Button.svg/640px-OpenSUSE_Button.svg.png'
	if'solaris'in A:return'https://upload.wikimedia.org/wikipedia/commons/thumb/2/25/Solaris_9_logo.svg/960px-Solaris_9_logo.svg.png'
	return'https://symbols.getvecta.com/stencil_240/79_fileserver.c500813aaa.png'
def draw_main(hosts,file_path,file_name,max_host_per_row=4):
	m='link';l='vertical';k='bottom';U=max_host_per_row;T='horizontal';S='Helvetica';R='#000000';F='center';V=drawpyo.File();V.file_path=file_path;V.file_name=file_name;C=drawpyo.Page('file=file');C.grid=0;C.background='#ffffff';n=drawpyo.diagram.text_format.TextFormat(fontColor=R,fontFamily=S,fontSize=10,align=F,direction=T,labelPosition=F);b=drawpyo.diagram.text_format.TextFormat(fontColor=R,fontFamily=S,fontSize=16,align=F,direction=T,labelPosition=F,bold=1);o=drawpyo.diagram.text_format.TextFormat(fontColor=R,fontFamily=S,fontSize=10,align=F,direction=T,labelPosition=F,verticalAlign=k,spacingBottom=45);p=drawpyo.diagram.text_format.TextFormat(fontColor=R,fontFamily=S,fontSize=10,align=F,direction=T,labelPosition=F,verticalAlign=k,spacingBottom=60);D={}
	for E in hosts:
		W=E[_C]
		if W not in D:D[W]=[]
		D[W].append(E)
	J=[['#2D8A5B','#F0F9F4','#144D3E'],['#7B61FF','#F2F0FF','#4A3BB1'],['#D97706','#FFFBEB','#92400E'],['#00A4A6','#E6F6F7','#147EBA'],['#E11D48','#FFF1F2','#9F1239'],['#4B5563','#F3F4F6','#1F2937']];G=0;A=75;X=A+50;K=50;L=100+X*U;c=drawpyo.diagram.Object(text_format=b,value=f"Company<br/>Location<br/>FQDN",page=C,width=A,height=A,position=(L+K,20),html=1,whiteSpace='nowrap',image='');q='text;html=1;strokeColor=none;fillColor=none;whiteSpace=nowrap;';c.apply_style_string(q);c.text_format=b;M=drawpyo.diagram.Object(value=f"Router<br/>127.0.0.1<br/>PfSense",page=C,width=A,height=A,position=(L+K,140));M.text_format=o;I=f"shape=image;verticalLabelPosition=bottom;verticalAlign=top;imageAspect=0;aspect=fixed;html=1;whiteSpace=nowrap;image={get_os_string(_H)};";M.apply_style_string(I);Y=drawpyo.diagram.Object(value=f"Public Internet",page=C,width=A,height=A,position=(L+K,330));I=f"shape=image;verticalLabelPosition=bottom;verticalAlign=top;imageAspect=0;aspect=fixed;html=1;whiteSpace=nowrap;image={get_os_string(_G)};";Y.apply_style_string(I);Y.text_format=p;r=[];x=len(D);N=[0,0];Z=0;d=[]
	for s in D:O=math.ceil(len(D[s])/U);d.append(O);Z+=O
	t=Z/2;e=0;f=0;u=Z>3
	for(v,O)in enumerate(d):
		e+=O;f=v
		if e>=t:break
	a=0;a=0
	for g in D:
		h=[]
		for E in D[g]:H=drawpyo.diagram.Object(value=f"{E[_D]}<br/>{E[_B]}<br/>{E[_A]}<br/>{E[_F]}",page=C,width=A,height=A);I=f"shape=image;verticalLabelPosition=bottom;verticalAlign=top;imageAspect=0;aspect=fixed;html=1;whiteSpace=nowrap;image={get_os_string(E[_A])};";H.apply_style_string(I);H.text_format=n;h.append(H)
		B=drawpyo.diagram.Object(page=C,value=f"{g}",autosize_margin=50);B.apply_style_string(f"html=1;fontSize=12;fontStyle=0;shape=mxgraph.aws4.group;grIcon=mxgraph.aws4.group_security_group;grStroke=0;strokeColor={J[G][0]};fillColor={J[G][1]};verticalAlign=top;align=left;spacingLeft=30;fontColor={J[G][2]};dashed=0;");G+=1
		if G>=len(J):G=0
		i,P=0,0
		for(y,H)in enumerate(h,start=1):
			if P>U-1:P=0;i+=1
			B.add_object(H);H.position_rel_to_parent=P*X,i*(X*1.25);P+=1
		B.resize_to_children();j=drawpyo.diagram.edges.Edge(page=C,source=B,target=M,label='127.0.0.1',label_position=-1,label_offset=15,endSize=40,startSize=40,rounded=True,waypoints=l,connection=m);B.height+=25
		if u:
			Q=0 if a<=f else 1
			if Q==1:j.apply_style_string('label_offset=-15;')
			w=Q*(L+K*3+A);B.position=w,N[Q];N[Q]+=B.height+50
		else:B.position=0,N[0];N[0]+=B.height+50
		a+=1;r.append(B)
	j=drawpyo.diagram.edges.Edge(page=C,source=Y,target=M,endSize=30,startSize=30,rounded=True,targetPerimeterSpacing=33,waypoints=l,connection=m);V.write()
def main():
	if len(sys.argv)>1:A=sys.argv[1]
	else:A=_E
	if len(sys.argv)>2:B=int(sys.argv[2])
	else:B=4
	C=os.getcwd();D='network_diagram.drawio';print('Parsing input file...');E=parse_csv(A);print('Parsed and sorted hosts.');print('Drawing diagram...');draw_main(E,C,D,B);print(f"Diagram generated at {C}{D}")
main()