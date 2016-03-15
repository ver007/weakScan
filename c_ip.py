import re
import sys
path=sys.argv[1]
path2=sys.argv[2]
f=open(path)
c_iplist=[]
#f1=open('newip.txt','a')
line=f.readline()
while line:
    line = f.readline()  
    ip=re.findall('(?<![\.\d])(?:\d{1,3}\.){3}\d{1,3}(?![\.\d])',line)
    #print ip[0]
    try:
        if re.match('^(10|127|172|192)+.\d+.\d+.\d+',ip[0]):
            pass
        else:
            print ip[0]
            ip2=ip[0]
            print ip2+">>>>>>>>>>>>>>>"
            c_iplist.append(ip2)
    except:
        pass
iplist=[]
iplist1=[]
f=open(path2,'a')
for line in c_iplist:
    print line
    ip=re.findall(r'\d+.\d+.\d+.',line)
    iplist.append(ip[0])
for ip in iplist:
    print ip
    if ip not in iplist1:
        iplist1.append(ip)
for ip in iplist1:
    for i in range(1,255):
        print ip
        ip1=ip+str(i)+'\n'
        f.write(ip1)
f.close