#!/usr/bin/env python
from lxml import etree

def main():
	doc = etree.parse("scan.xml")
	for x in doc.xpath("//host[ports/port[state[@state='open']]]"):
		for addr in x.xpath("address/@addr"):
			print addr
		for open_p in x.xpath("ports/port[state[@state='open']]"):
			print '	','	'.join([str(items) for items in open_p.attrib.values()])
			print '	', '\n		'.join([str(x) for child in list(open_p) for x in child.attrib.iteritems()])



if __name__ == "__main__":
	main()

