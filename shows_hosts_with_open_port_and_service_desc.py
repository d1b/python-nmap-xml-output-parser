#!/usr/bin/env python
from lxml import etree
from optparse import OptionParser
from sys import exit

def main(file_name):
	doc = etree.parse(file_name)
	for x in doc.xpath("//host[ports/port[state[@state='open']]]"):
		for addr in x.xpath("address/@addr"):
			print addr
		for open_p in x.xpath("ports/port[state[@state='open']]"):
			print '	','	'.join([str(items) for items in open_p.attrib.values()])
			print '	', '\n		'.join([str(x) for child in list(open_p) for x in child.attrib.iteritems()])



def parse_opts():
	parser = OptionParser()
	parser.add_option("-f", "--file-name", action="store", dest="file_name", help = "the filename of the nmap scan")
	(options, args) = parser.parse_args()
	if options.file_name is None:
		print "you MUST enter a file name, see -h"
		exit(1)
	main(options.file_name)

if __name__ == "__main__":
	parse_opts()
