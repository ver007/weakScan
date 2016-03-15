#!/usr/bin/env python
#encoding=utf-8
#http://notwhy.cn

from bs4 import BeautifulSoup
#开始fuzz敏感的文件
class CrawlUrl(object):
	def __init__(self,urlobj):
		super(CrawlUrl, self).__init__()
		self.urlobj = urlobj
		self.soup = BeautifulSoup(self.urlobj.text,'html.parser')
		#存放第一层URL的列表
		self.url_link = []
		self.length_404 = self.html.length_404()
		self.script = self.fuzzJudge()

	#检测公共的404页面 判断长度是否相等 后面继续添加
	def length_404(self):
		test1 = http_request(self.urlobj.url + 'a_404_commen_dir')
		test2 = http_request(self.urlobj.url + 'a_404_commen_url.htm')
		if test1 == test2:
			return len(test1)
		else:
			return false

	#爬虫 爬取目录 a标签下的内容
	def get_a_href(self):
		for tag in self.soup.find_all('a'):
			#print dir(self.soup)
			if tag.attrs.has_key('href'):
				link = tag.attrs['href']
				self.url_link.append(link)
		return list(set(self.url_link))

	#选择fuzz的类型如php asp aspx jsp
	def fuzzJudge(self):
		pass

	def test(self):
		return 'test'