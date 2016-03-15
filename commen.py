#!/usr/bin/env python
#encoding=utf-8
#http://notwhy.cn
import libs.requests as requests
import libs.requests as __requests__
import threading
import time
import nmap
import Queue
from config import *
from libs.fuzzurl import FuzzWeakFile
from libs.crawl import CrawlUrl
from libs.tldextract import extract, TLDExtract
from itertools import chain
from result import *
import re

#将有效地URL存入列表
global alieve_url
alieve_url = []
global scan_result
alieve_url = []
tmp_dir = []
separation = '/'
global scan_result
scan_result = []
global quchong
quchong = []

#定义requests请求 返回状态码
def http_request(url, body_content_workflow=False, allow_redirects=allow_redirects):
	try:
		result = requests.get(url, 
			stream=body_content_workflow, 
			headers=headers, 
			timeout=timeout, 
			proxies=proxies,
			allow_redirects=allow_redirects,
			verify=allow_ssl_verify
			)
		return result
	except Exception, e:
		# 返回空的requests结果对象
		return __requests__.models.Response()

#检测网站存活情况
def check_isalive(url):
	#http://219.143.252.108/console 这个不要改
	result = http_request(url, allow_redirects=False)
	if result.status_code: # 存在状态码
		return True
	else:
		return False

def findStr(host, subStr, findCnt):
	listStr = host.split(subStr,findCnt)
	if len(listStr) <= findCnt:
		return -1
	return len(host)-len(listStr[-1])-len(subStr)

#检查网站是否存活的多线程
class CheckAlieveThreads(threading.Thread):
	def __init__(self,queue):
		super(CheckAlieveThreads,self).__init__()
		self.queue = queue

	def run(self):
		while True:
			if self.queue.empty():
				break
			else:
				try:
					url = self.queue.get_nowait()
					if(':/' not in url):
						url = 'http://' + url
					print '[*] Check %s alieve or not\n' % url,
					if check_isalive(url) == True:
						alieve_url.append(url)
				except:
					break
'''
#检查公共的URL线程 例如/etc/hosts 暂时废弃
class CheckCommentThreads(threading.Thread):
	def __init__(self,queue):
		super(CheckCommentThreads,self).__init__()
		self.queue = queue

	def run(self):
		while True:
			if self.queue.empty():
				break
			else:
				try:
					url = self.queue.get_nowait()
					print http_request(url)
				except:
					break
'''
#fuzzurl的线程
class FuzzUrlThreads(threading.Thread):
	def __init__(self,queue,web_type):
		super(FuzzUrlThreads,self).__init__()
		self.queue = queue
		self.web_type = web_type

	def run(self):
		while True:
			if self.queue.empty():
				break
			else:
				try:
					#print all_lst
					url = self.queue.get_nowait()
					host,url_lst = FuzzWeakFile(url,self.web_type).fuzzFile()
					for _ in url_lst:
						#if {host:_} not in scan_result:
						scan_result.append({host:_})
				except Exception,e:
					print e
					break

#扫描端口的线程
class NmapThreads(threading.Thread):
	def __init__(self,queue):
		super(NmapThreads,self).__init__()
		self.queue = queue

	def findStr(self,host, subStr, findCnt):
	    listStr = host.split(subStr,findCnt)
	    if len(listStr) <= findCnt:
	        return -1
	    return len(host)-len(listStr[-1])-len(subStr)

	def run(self):
		while True:
			if self.queue.empty():
				break
			else:
				try:
					#先扫描通过前边已经判断出存活的端口 进行扫描
					alieve_port = []
					#nmap扫描出的port
					nmap_port = []
					#初步方案是把alieve_port和nmap_port合并起来再进行扫描 以防止大站nmap扫描不出来http端口
					ip = self.queue.get_nowait()
					if ',' in ip:
						lst = ip.split(',')
						ip = lst[0]
						i = 1
						for _ in lst[1:]:
							alieve_port.append(lst[i])
							i = i + 1
					nm = nmap.PortScanner()

					nm.scan(ip,arguments = nmapArguments)
					for line in nm.csv().split('\n'):
						if 'open' in line:
							portInfo = line[0:line.find('open') + 4].split(';')
							nmap_port.append(portInfo[2])
					#print alieve_port
					nmap_port += alieve_port
					nmap_port = list(set(nmap_port))
					if len(nmap_port) > 10:
						nmap_port = nmap_port[:5]
					#m6go.com
					for port in nmap_port:
					#'''
						if int(port) in range(80,90) or int(port) in range(8000,8201):
							#先加上http进行访问 带端口的
							if int(port) == 80:
								url = 'http://' + ip + '/'
							else:
								url = 'http://' + ip + ':' + port + '/'
							url_noport = 'http://' + ip + '/'
							print ('start scan ' + ip + ':' + port)
							#以后往这里加上一个检查端口判断的

							#检查扫描的端口是否有效 如果无效跳过
							if check_isalive(url):
								#处理压缩文件 hostname.zip  如www.baidu.com/www.baidu.com.zip  baidu.zip
								#print extract(url)
								if extract(url).suffix != '':
									for _ in ['.zip','.rar','.tar.gz','.tar.bz2','.tgz']:
										if http_request(url + extract(url).domain + _,allow_redirects = False).status_code == 200 and "accept-ranges: bytes" in  str(http_request(url + extract(url).domain + _,allow_redirects = False).headers):
											print '[*]' + ' [200] ' + url + extract(url).domain + _,
											scan_result.append({ip:{'status': 200,'url':url + extract(url).domain + _}})
										if http_request(url + extract(url).subdomain + extract(url).domain + extract(url).suffix + _,allow_redirects = False).status_code == 200 and "accept-ranges: bytes" in  (http_request(url + extract(url).subdomain + extract(url).domain + extract(url).suffix + _,allow_redirects = False).headers):
											print '[*]' + ' [200] ' + url + extract(url).subdomain + '.' + extract(url).domain + '.' + extract(url).suffix + _,
											scan_result.append({ip:{'status':200,'url':url + extract(url).subdomain + '.' + extract(url).domain + '.' + extract(url).suffix + _}})

								urlobj = http_request(url)

								if str(urlobj) == '<Response [None]>':
									urlobj = http_request('https://' + ip + ':' + port)


								#判断是否有报目录漏洞 如Index of 如果有则不往下进行扫描
								if '<h1>Index of /</h1>' in urlobj.text:
									print '[*] ' + url + '\t存在Index of爆目录漏洞'.decode("utf8")
									if url.count(':') > 1:
										scan_result.append({url[self.findStr(url,'/',2) + 1:self.findStr(url,':',2)]: {'status': 200, 'url': url + '\tIndex of vul'}})
									elif url.count('/') > 2:
										scan_result.append({url[self.findStr(url,'/',2) + 1:self.findStr(url,'/',3)]: {'status': 200, 'url': url + '\tIndex of vul'}})
									else:
										scan_result.append({url[self.findStr(url,'/',2) + 1:]: {'status': 200, 'url': url + '\tIndex of vul'}})
									#scan_result.append({url: {'status': 200, 'url': url + '\tIndex of vul'}})
								else:
									#调入fuzz类  开始进行fuzz操作 取出a标签下的内容
									fuzz_url = CrawlUrl(urlobj).get_a_href()
									#global web_type 
									web_type = 'commen'
									#处理fuzz_url 把没用的链接先去掉 直接在列表中循环删除不行 需要设置一个替代值
									fuzz_url1 = fuzz_url[::]
									for _ in fuzz_url1:
										#处理别站的url
										if 'http' in _ and url not in _:
											fuzz_url.remove(_)
										#处理javascript跳转 如javascript:check();
										elif 'javascript' in _:
											fuzz_url.remove(_)
										#处理转向自身的#和baidu.com/#adfg这样的模式
										elif '#' in _:
											fuzz_url.remove(_)
										#后续继续添加更加变态的URL模式



									#这里开始判断fuzz的类型
									#1.根据第一层url链接中是否含有.php判断

									#print fuzz_url
									for line in fuzz_url:
										if '.php' in line:
											web_type = 'php'
											break
										elif '.aspx' in line:
											web_type = 'aspx'
											break
										elif '.asp' in line:
											web_type = 'asp'
											break
										elif '.jsp' in line or '.do' in '.jsp' or '.action' in line:
											web_type = 'jsp'
											break
										else:
											continue

																		
									#2.根据index.php是否返回正常
									if web_type != 'commen':
										pass
									else:
										if len(http_request(url + 'index.php').text) != len(http_request(url + 'index.asp').text):
											if len(http_request(url + 'index.php').text) == len(urlobj.text):
												web_type = 'php'
											elif len(http_request(url + 'index.asp').text) == len(urlobj.text):
												web_type = 'asp'
											elif len(http_request(url + 'index.aspx').text) == len(urlobj.text):
												web_type = 'aspx'															
											elif len(http_request(url + 'index.jsp').text) == len(urlobj.text):
												web_type = 'jsp'
											else:
												pass
									#先这样简单判断 后面会加上新的判断方式


									#http://172.20.2.7:8080/exam/index.jsp 将二级目录下的URL加入
									url_self = str(urlobj.url)
									if url_self != 'None':
										fuzz_url.append(url_self)
									#print fuzz_url
									#取出fuzz_url的dir目录 为下一步fuzz做基础
									#[u'd/', u'f', u'b/', u'/a', u'/a.php', u'e/eee.php', u'g/', u'c/index.php']
									fuzz_dir = []
									fuzz_url_dir = []
									#print fuzz_url
									for _ in fuzz_url:
										if url in _:
											fuzz_dir.append(_.replace(url,''))
										else:
											fuzz_dir.append(_)

									fuzz_dir = list(set(fuzz_dir))
									#print fuzz_dir
									#处理a标签
									for url_dir in fuzz_dir:
										if '.' in url_dir:
											if '/' in url_dir:
												fuzz_url_dir.append(url_dir[0:url_dir.rfind('/')+1])
										else:
											fuzz_url_dir.append(url_dir)
									#print fuzz_url_dir
									#fuzz_url_dir [u'', u'd/', u'f', u'b/', u'/a', u'/', u'e/', u'g/', u'c/',u'/yl/st/News?id=103562']
									fuzz_url_dir1 = []
									for aa in fuzz_url_dir:
										if aa != '' and aa != '/' and 'http' not in aa:
											if aa[0] == '/':
												if aa == '//':
													fuzz_url_dir1.append(url[:-1])
												elif aa[-1] == '/':
													fuzz_url_dir1.append(url + aa[1:][:-1])
												elif '?' in aa:
													#print url[:-1] + aa[:aa.rfind('/')]
													fuzz_url_dir1.append(url[:-1] + aa[:aa.rfind('/')])
												else:
													fuzz_url_dir1.append(url + aa[1:])
											elif aa[-1] != '/':
												if '?' in aa:
													#print url[:-1] + aa[:aa.rfind('/')]
													fuzz_url_dir1.append(url + aa[:aa.rfind('/')])
												else:
													fuzz_url_dir1.append(url + aa)
											else:
												fuzz_url_dir1.append(url + aa[:-1])
									#fuzz_url_dir1 [u'd/', u'f/', u'b/', u'a/', u'e/', u'g/', u'c/']		
									fuzz_dir = fuzz_url_dir1
									#print fuzz_dir
									#将重复的80端口去掉 如果都没有则添加上一个 http://127.0.0.1/ http://127.0.0.1:8080/
									if url not in fuzz_dir:
										fuzz_dir.append(url[:-1])

									fuzz_dir = list(set(fuzz_dir))
									#print fuzz_dir
									#去除汉字的链接
									hanzi = []
									hanzi.append(url[:-1])

									for _ in fuzz_dir:
										#print _ + '0000000000000000'
										hanzi_pattern = re.compile(u'[\u4e00-\u9fa5]+')
										match = hanzi_pattern.search(_)
										if not match:
											hanzi.append(_)
									fuzz_dir = list(set(hanzi))
									#print fuzz_dir
									#判断是否要fuzz的dir太长 例如电影什么的dir可能比较多 暂时没想到什么好的去重复办法 先取前10个
									if len(fuzz_dir) > 10:
										fuzz_dir = fuzz_dir[:10]
										if url[:-1] not in fuzz_dir:
											fuzz_dir.append(url[:-1])
									#print fuzz_dir
									#print url
									
									#调入fuzz类 还是进行fuzz操作
									queue = Queue.Queue()
									for url in fuzz_dir:
										#fuzz_obj = FuzzWeakFile(http_request(url),web_type)
										queue.put(url)
									threads = []
									for i in xrange(10):
										threads.append(FuzzUrlThreads(queue,web_type))
									for t in threads:
										t.start()
									for t in threads:
										t.join()

								#results.append(scan_result)
								#report(scan_result,start_time)
						#'''
		
				except Exception,e:
					print e
					break



