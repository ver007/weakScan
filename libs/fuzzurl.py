#!/usr/bin/env python
#encoding=utf-8
#http://notwhy.cn

from bs4 import BeautifulSoup
from config import *
import libs.requests as requests
import libs.requests as __requests__
from itertools import chain
global fuzz_url_lst
fuzz_url_lst = []
#定义requests请求 返回状态码
def http_request(url, body_content_workflow=False, allow_redirects=False):
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

#开始fuzz敏感的文件
class FuzzWeakFile(object):
	def __init__(self,url,web_type):
		super(FuzzWeakFile, self).__init__()
		self.url = url
		self.urlobj = http_request(self.url)
		self.web_type = web_type

	def page_not_find(self,urlobj,commen_404):
		if len(urlobj.text) != commen_404 and len(urlobj.text) != 0:
			#print str(1111111111)+ urlobj.url
			if str(urlobj.status_code).startswith('5'):
				return False
			for _ in commen_error_find.split(','):
				if unicode(_) in urlobj.text:
					return False
			return True
		#处理域名301 302直接跳转的
		elif urlobj.status_code in [301,302]:
			return True
	#fuzz主函数
	def fuzzFile(self):
		lst = []
		#判断是否有公共的404页面
		test1 = len(http_request(self.url + '/a_404_commen_dir').text)
		test2 = len(http_request(self.url + '/a_404_commen_url.htm').text)
		if test1 == test2:
			commen_404 = test1
		else:
			commen_404 = 1
		#print commen_404

		#print self.web_type + self.url
		#处理已经判断出类型是php的文件

		if self.web_type == 'php':
			filename = php_file_lst
		elif self.web_type == 'aspx':
			filename = aspx_file_lst
		elif self.web_type == 'jsp':
			filename = jsp_file_lst
		elif self.web_type == 'asp':
			filename = asp_file_lst
		else:
			filename = 'not_find_type'
		add = ['rar','zip']
		#print self.web_type
		#if self.web_type == 'commen':
			#add.remove(self.web_type)
		if self.url.count('/') > 2:
			#如果判断不出脚本类型的话就吧/dir/dir.web_type去掉 fuzz dir/dir.zip类似的文件
			
			for _ in add:
				url_res1 = http_request(self.url + self.url[self.url.rfind('/'):] + '.' + _)
				#print self.url + self.url[self.url.rfind('/'):] + '.' + _
				if self.page_not_find(url_res1,commen_404):
					#变成http://url/dir/dir.zip rar php
					#print url_res1.url
					if url_res1.status_code == 200 and len(url_res1.text) != commen_404 and "accept-ranges: bytes" in str(url_res1.headers):
						#加入列表当中
						#print self.url + self.url[self.url.rfind('/'):] + '.' + _
						lst.append({'status': url_res1.status_code, 'url': self.url + self.url[self.url.rfind('/'):] + '.' + _})
						print '[*]' + ' [200] '+ self.url + self.url[self.url.rfind('/'):] + '.' + self.web_type

				url_res2 = http_request(self.url + '.' + _)
				if self.page_not_find(url_res2,commen_404):
					#print self.url + '.' + _ + str(url_res2.status_code)
					#变成http://url/dir.zip rar php
					if url_res2.status_code == 200 and len(url_res2.text) != commen_404  and "accept-ranges: bytes" in str(url_res2.headers):
						#加入列表当中
						#print self.url + self.url[self.url.rfind('/'):] + '.' + _
						lst.append({'status': 200, 'url': self.url + '.' + _})
						print '[*]' + ' [200] '+ self.url + self.url[self.url.rfind('/'):] + '.' + self.web_type
			#开始对dir下fuzz所必要的文件
					
			if str(filename) != 'not_find_type':
				for line in filename:
					#开始扫描php.txt中带有/的文件
					if line.startswith('/'):
						url_res3 = http_request(self.url + line.split('\t')[0].strip())
						#print self.url + line.split('\t')[0].strip()
						if self.page_not_find(url_res3,commen_404):
							#print str(self.page_not_find(url_res,commen_404)) + url_res.url
							#状态和tag同时存在
							if 'status=' in str(line.split('\t')) and 'tag=' in str(line.split('\t')):
								#print str(line.split('\t'))[str(line.split('\t')).find("\"") + 1:str(line.split('\t')).rfind("\"")]
								if url_res3.status_code == 200 and str(line.split('\t'))[str(line.split('\t')).find("\"") + 1:str(line.split('\t')).rfind("\"")] in url_res3.text:
									#加入列表当中
									lst.append({'status': url_res3.status_code, 'url': self.url + line.split('\t')[0]})
									print '[*]' + ' [' + str(url_res3.status_code) + '] ' + self.url + line.split('\t')[0].strip()
							elif 'status=' in str(line.split('\t')):
								if url_res3.status_code == 200:
									#加入列表当中
									lst.append({'status': url_res3.status_code, 'url': self.url + line.split('\t')[0]})
									print '[*]' + ' [' + str(url_res3.status_code) + '] ' + self.url + line.split('\t')[0].strip()
							elif 'tag=' in str(line.split('\t')):
								#print str(line.split('\t'))[str(line.split('\t')).find("\"") + 1:str(line.split('\t')).rfind("\"")]
								if str(line.split('\t'))[str(line.split('\t')).find("\"") + 1:str(line.split('\t')).rfind("\"")] in url_res3.text:
									#加入列表当中
									lst.append({'status': url_res3.status_code, 'url': self.url + line.split('\t')[0]})
									print '[*]' + ' [' + str(url_res3.status_code) + '] ' + self.url + line.split('\t')[0].strip()
							elif url_res3.status_code not in [400,404,403] and url_res3.status_code != None:
								#加入列表当中
								lst.append({'status': url_res3.status_code, 'url': self.url + line.split('\t')[0]})
								print '[*]' + ' [' + str(url_res3.status_code) + '] ' + self.url + line.split('\t')[0].strip()
		if self.url.count('/') == 2:
			if self.web_type == 'php':
				domain_file = list(chain(php_file_lst,php_config_file_lst,domain_commen_file_lst))
			elif self.web_type == 'aspx':
				domain_file = list(chain(domain_commen_file_lst,aspx_file_lst))
			elif self.web_type == 'jsp':
				domain_file = list(chain(domain_commen_file_lst,jsp_file_lst))
			elif self.web_type == 'asp':
				domain_file = list(chain(domain_commen_file_lst,asp_file_lst))
			elif self.web_type == 'commen':
				domain_file = list(chain(php_file_lst,aspx_file_lst,jsp_file_lst,asp_file_lst,domain_commen_file_lst))#[php_file_obj,aspx_file_obj,asp_file_obj,jsp_file_obj,domain_commen_file_obj]
			#print domain_file									
			for line in domain_file:
				if line.startswith('/'):
					url_res = http_request(self.url + line.split('\t')[0].strip())
					#print self.url + line.split('\t')[0].strip()
					if self.page_not_find(url_res,commen_404):
						#print self.url + line.split('\t')[0].strip() + str(url_res.status_code)	#状态和tag同时存在
						if 'status=' in str(line.split('\t')) and 'tag=' in str(line.split('\t')):
							if url_res.status_code == 200 and str(line.split('\t'))[str(line.split('\t')).find("\"") + 1:str(line.split('\t')).rfind("\"")] in url_res.text:
								#加入列表当中
								lst.append({'status': url_res.status_code, 'url': self.url + line.split('\t')[0]})
								print '[*]' + ' [' + str(url_res.status_code) + '] ' + self.url + line.split('\t')[0].strip()
						elif 'status=' in str(line.split('\t')):
							if url_res.status_code == 200:
								#加入列表当中
								lst.append({'status': url_res.status_code, 'url': self.url + line.split('\t')[0]})
								print '[*]' + ' [' + str(url_res.status_code) + '] ' + self.url + line.split('\t')[0].strip()
						elif 'tag=' in str(line.split('\t')):
							if str(line.split('\t'))[str(line.split('\t')).find("\"") + 1:str(line.split('\t')).rfind("\"")] in url_res.text:
								#加入列表当中
								lst.append({'status': url_res.status_code, 'url': self.url + line.split('\t')[0]})
								print '[*]' + ' [' + str(url_res.status_code) + '] ' + self.url + line.split('\t')[0].strip()
						elif url_res.status_code not in [400,404,403] and url_res.status_code != None:
							#加入列表当中
							lst.append({'status': url_res.status_code, 'url': self.url + line.split('\t')[0]})
							print '[*]' + ' [' + str(url_res.status_code) + '] ' + self.url + line.split('\t')[0].strip().decode('utf-8')
		
		#如果单个扫描结果大于30 可能有个公共的错误 返回一个主域名
		if len(lst) > 20:
			lst = []#lst[:1]
			#print lst
		if self.url.count(':') > 1:
			return self.url[self.findStr(self.url,'/',2) + 1:self.findStr(self.url,':',2)],lst
		elif self.url.count('/') > 2:
			return self.url[self.findStr(self.url,'/',2) + 1:self.findStr(self.url,'/',3)],lst
		else:
			return self.url[self.findStr(self.url,'/',2) + 1:],lst
		

	def findStr(self,host, subStr, findCnt):
	    listStr = host.split(subStr,findCnt)
	    if len(listStr) <= findCnt:
	        return -1
	    return len(host)-len(listStr[-1])-len(subStr)

	def test(self):
		return 'test'
