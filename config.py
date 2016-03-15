#!/usr/bin/env python
#encoding=utf-8
#http://notwhy.cn
import time
#设置http header头
#headers={'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/38.0.2125.111 Safari/537.36 BBScan/1.0'}
#加入Google的header 绕过云加速
headers = {
    "Connection": "keep-alive",
    "Cache-Control": "max-age=0",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Upgrade-Insecure-Requests": "1",
    "User-Agent": "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36",
    "Accept-Encoding": "gzip, deflate, sdch",
    "Accept-Language": "zh-CN,zh;q=0.8"}
#超时时间
timeout = 5

#是否允许URL重定向
allow_redirects = True

#是否开启https服务器的证书校验
allow_ssl_verify = False

# 代理配置
proxies = {
	# "http": "http://user:pass@10.10.1.10:3128/",
	# "https": "http://10.10.1.10:1080",
	# "http": "http://127.0.0.1:8118", # TOR 洋葱路由器
}

nmapArguments = '-sT -P0 -p T:80-90,8080-8200'

commen_error_find = 'not found,Not Found,HTTP Status 404,未找到,不存在,Error,设置拦截,401 Authorization'#,401 未授权

php_file = './dict/php.txt'
aspx_file = './dict/aspx.txt'
jsp_file = './dict/jsp.txt'
asp_file = './dict/asp.txt'
php_config_file = './dict/php_config.txt'
commen_file = './dict/commen.txt'
domain_commen_file = './dict/domain_commen.txt'
#把所以类型的文件先取出来

global php_file_lst,aspx_file_lst,jsp_file_lst,aspx_file_lst,php_config_file_lst,domain_commen_file_lst
php_file_lst =[]
aspx_file_lst = []
jsp_file_lst = []
asp_file_lst = []
php_config_file_lst = []
domain_commen_file_lst = []
#程序开始时间
start_time = time.time()

