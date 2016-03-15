#!/usr/bin/env python
#encoding=utf-8
#http://notwhy.cn

import glob
import time
import sys
import urlparse
import socket
import ipaddress
from libs.cmdline import parse_args
from commen import *
from config import *
import Queue
import time
from result import *
class infoScanner(object):
	def __init__(self,host):
		self.host = host

	#获取url的协议 地址 路径
	@staticmethod
	def parse_url(host):
		urlobj = urlparse.urlparse(host)
		if not urlobj.netloc:
			urlobj = urlparse.urlparse('http://' + host)
		assert(urlobj.netloc != '')
		return urlobj.scheme,urlobj.netloc,urlobj.path if urlobj.path else '/'
		
def init_rules():
	php_file_obj = open(php_file,'rb')
	aspx_file_obj = open(aspx_file,'rb')
	jsp_file_obj = open(jsp_file,'rb')
	asp_file_obj = open(asp_file,'rb')
	php_config_file_obj = open(php_config_file,'rb')
	domain_commen_file_obj = open(domain_commen_file,'rb')
	for _ in php_file_obj.readlines():
	    php_file_lst.append(_)
	for _ in aspx_file_obj.readlines():
	    aspx_file_lst.append(_)
	for _ in jsp_file_obj.readlines():
	    jsp_file_lst.append(_)
	for _ in asp_file_obj.readlines():
	    asp_file_lst.append(_)
	for _ in php_config_file_obj.readlines():
	    php_config_file_lst.append(_)
	for _ in domain_commen_file_obj.readlines():
	    domain_commen_file_lst.append(_)

if __name__ == '__main__':
	start_time = time.time()
	init_rules()
	reload(sys)
	sys.setdefaultencoding('utf8') 
	global results
	results = []
	args = parse_args()
	#保存所有的file文件到列表
	if args.d:
		all_files = glob.glob(args.d + '/*.txt')
	elif args.f:
		all_files = [args.f]
	else:
		all_files = ['temp']

	#如果是目录下文件 一个一个进行扫描
	for file in all_files:
		if args.host:
			lines = [args.host]
		else:
			with open(file) as inFile:
				lines = inFile.readlines()
	#'''
		scan_ips = []
		#根据CIDR产生 将数据保存到network列表中
		scan_network_ip = []
		#根据常见端口产生试探性的URL 判断IP地址是否有效 如果无效排除nmap及后续扫描
		heuristic_url = []
		for line in lines:
			if line.strip():
				host = line.strip()
				#获取初始化URL 保留端口号
				scheme,url,path = infoScanner.parse_url(host)
				#print scheme,url,path
				try:
					#把端口给去掉只保留URL地址 然后取其IP地址 进行CIDR运算
					ip = socket.gethostbyname(url.split(':')[0])
					if ':' in url:
						port  = url.split(':')[1]
						#将最初的URL装入列表
						heuristic_url.append(host)
					scan_ips.append(url)
					#nm = nmap.PortScanner()
					#test = nm.scan(ip,arguments='-sT -P0 -p T:21,22,80,8080')
				except Exception,e:
					scan_ips.append(url)
					print url.split(':')[0] + ' getip ' + str(e)
				#开始调用nmap
		if args.network != 32:
			for ip in scan_ips:
				try:
					ip = socket.gethostbyname(url.split(':')[0])
				except Exception,e:
					print e
					print 'domain to ip error  please provide an availably ip'
					break
				ips = ipaddress.IPv4Network(u'%s/%s' % (ip, args.network), strict=False).hosts()
				for _ip in ips:
					_ip = str(_ip)
					scan_network_ip.append(_ip)
		else:
			scan_network_ip = scan_ips
		#将80 8080端口装入试探列表
		for ip in scan_network_ip:
			if ':' in ip:
				ip =  ip[:findStr(ip,':',1)]
			heuristic_url.append(ip + ':80')
			heuristic_url.append(ip + ':8080')
		
		#加入多线程 
		queue = Queue.Queue()
		#判断网站是否有效 即网站80 8080是否能够访问
		for url in heuristic_url:
			#print url
			queue.put(url)
		threads = []
		for i in xrange(100):    
			threads.append(CheckAlieveThreads(queue))
		for t in threads:
			t.start()
		for t in threads:
			t.join()


		#将不能访问80或者8080端口的IP地址从扫描列表中剔除
		alieve_ip = []
		#print alieve_url
		for url in alieve_url:
			#把端口和协议信息也加进去 如果没有端口加上80
			#print url
			#print extract(url)

			#把协议信息加上去 区分http和https
			#把端口信息加上去 如果扫描不出端口 就用自带的端口
			if '://' in url:
				#得到协议头
				httpHead = url[:url.find('://')] + '://'
				#得到端口位置 去除端口
				if '/' in url[findStr(url,':',2):]:
					port = url[findStr(url,':',2):][findStr(url,'/',3):]
					#print port + '1'
				else:
					port = url[findStr(url,':',2) + 1:]
					#print port
				if port == '':
					port = '80'
			alieve_ip.append(httpHead + ',' + url[url.find('://')+3:findStr(url,':',2)] + ',' + port)

		#去重得到不重复的IP
		alieve_ip = list(set(alieve_ip))
		#端口扫描

	zhongzhuan = []
	for _ in alieve_ip:
		zhongzhuan.append(_.split(',')[1])
	zhongzhuan = list(set(zhongzhuan))
	final = zhongzhuan
	for _ in alieve_ip:
		for domain in zhongzhuan:
			if _.split(',')[1] in domain:
				final[final.index(domain)] = domain + ',' + _.split(',')[2]
	#print alieve_ip
	alieve_ip = final
	#print alieve_ip
	#'''
	queue = Queue.Queue()
	for url in alieve_ip:
		queue.put(url)
	threads = []
	for i in xrange(100):
		threads.append(NmapThreads(queue))
	for t in threads:
		t.start()
	for t in threads:
		t.join()

	#print scan_result
	report(scan_result,start_time)
	#'''
