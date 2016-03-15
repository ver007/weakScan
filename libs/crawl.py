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

	#爬虫 爬取目录 a标签下的内容
	def get_a_href(self):
		#print self.soup.find_all('a')
		for tag in self.soup.find_all('a'):
			if tag.attrs.has_key('href'):
				link = tag.attrs['href']
				self.url_link.append(link)
		return list(set(self.url_link))

	def test(self):
		return 'test'