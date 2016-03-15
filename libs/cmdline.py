#!/usr/bin/env python
#encoding=utf-8
#http://notwhy.cn

import argparse
import sys
import os

def parse_args():
	parser = argparse.ArgumentParser(formatter_class=argparse.RawTextHelpFormatter,
									description = 'A web vulnerability scanner by whynot',
									epilog = 'If you use this program, please do not used for illegal purposes',
									usage = '%(prog)s [options]'
									)
	#单个或多个主机
	parser.add_argument('--host',metavar = 'host',type = str,default = '',help = 'scan a simple host')
	#进程数 默认是100
	#parser.add_argument('-p',metavar = 'processes',type = int,default = 10,help = 'specify the numbers of processes')
	#线程数 默认是20
	#parser.add_argument('-t',metavar = 'threads',type = int,default = 20,help = 'specify the numbers of threads')
	#从指定文件中读取host
	parser.add_argument('-f',metavar = 'weakfile',default = '',help = 'load the host from weakfile')
	#从指定目录中读取文件
	parser.add_argument('-d',metavar = 'weakdirectory',default = '',help = 'load all *.txt from weakdirectory')
	#通过CIDR方式确定扫描范围 
	parser.add_argument('--network',metavar = 'CIDR',type = int,default = 32,help = 'scan CIDR host should be int between 24 and 31')
	#扫描完成时是否选择用浏览器打开
	#parser.add_argument('--browser',default = False,help = 'open web browser to view the repoat after scan finished')

	#weakscan版本
	parser.add_argument('-v',action='version',version='%(prog)s 1.0 By wooyun whynot (http://notwhy.cn)')

	if(len(sys.argv)  == 1):
		sys.argv.append('-h')
	args = parser.parse_args()
	check_args(args)
	return args


def check_args(args):
	if not args.f and not args.d and not args.host:
		msg = 'please use -f to set a correct file name or use -d to set a directory or use --host to set a host'
		raise Exception(msg)

	if args.f and not os.path.isfile(args.f):
		raise Exception('file not found: %s' % args.f)

	if args.d and not os.path.isdir(args.d):
		raise Exception('directory not found: %s' % args.d)

	args.network = int(args.network)
	if not (args.network >=24 and args.network <=32):
		raise Exception('--network must be an integer between 24 and 32')
