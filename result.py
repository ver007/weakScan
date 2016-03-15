#!/usr/bin/env python
#encoding=utf-8


from libs.report import TEMPLATE_host, TEMPLATE_html, TEMPLATE_list
from string import Template
import webbrowser,os
import time
def report(scan_result,start_time):
	t_html = Template(TEMPLATE_html)
	t_host = Template(TEMPLATE_host)
	t_list = Template(TEMPLATE_list)

	html_doc = ''
	keys = []
	for dic in scan_result:
		for key in dic:
			keys.append(key)
			#print dic[key]['status']
	global i
	i = 0
	keys = list(set(keys))
	def test(scan_result,keys,i):
		aa = []
		for dic in scan_result:
			try:
				aa.append(dic[keys[i]])
			except Exception,e:
				#print e
				pass
		i = i + 1
		return keys[i-1],aa
	m = 0
	while((m + 1) <= len(keys)):
		_str = ''
		key,aa = test(scan_result,keys,m)
		for _ in aa:
			_str += t_list.substitute( {'status': _['status'], 'url': _['url'].decode()} )
		_str = t_host.substitute({'host': key, 'list': _str})
		m = m+1
		html_doc += _str
	cost_time = time.time() - start_time
	cost_min = int(cost_time / 60)
	cost_seconds = '%.2f' % (cost_time % 60)
	html_doc = t_html.substitute({'cost_min': cost_min, 'cost_seconds': cost_seconds, 'content': html_doc})

	report_name = time.strftime('%Y%m%d_%H%M%S', time.localtime()) + '.html'
	with open('report/%s' % report_name, 'w') as outFile:
	    outFile.write(html_doc)
	print 'Report saved to report/%s' % report_name
	webbrowser.open_new_tab(os.path.abspath('report/%s' % report_name))