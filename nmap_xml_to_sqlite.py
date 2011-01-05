#!/usr/bin/env python
from lxml import etree
import sqlite3
import os
import datetime
from shows_hosts_with_open_port_and_service_desc import parse_opts


__program__ = 'python_convert_nmap_xml_to_sqlite_db'
___author__ = 'dave b. <db@d1b.org>'
__license__ = 'GPL v2'

class nmap_xml_to_sqlite:
	def __init__(self, filename, store_p=os.path.expanduser('~/.nmap_pdb/')):
		self.filename = filename
		self.store_p = store_p
		self._db_name = "nmap.db"
		self.conn = None
		self.cursor = None

	def create_store_dir(self):
		""" create the store directory if it doesn't exist """
		if not os.path.exists(self.store_p):
			os.mkdir(self.store_p)

	def connect_to_db(self):
		""" connect to the database """
		self.conn = sqlite3.connect(self.store_p + self._db_name)
		self.cursor = self.conn.cursor()

	def create_db(self):
		""" create the database tables if they don't exist """
		self.cursor.execute("""create table if not exists
		hosts(addr text, hostname text, scan_time datetime,
		unique(addr, hostname, scan_time))""")
		self.cursor.execute("""create table if not exists
		open_port (addr text, port integer, product text,
		protocol text, scan_time datetime, name text,
		servicefp text, version text,
		unique(protocol, port, addr, scan_time))""")
		self.cursor.execute("""create table if not exists scan
		(scan_time datetime, args text, unique (scan_time, args))""")

	def insert_scan_into_db(self, time_of_scan, args):
		""" insert a scan into the database """
		sql_statement = """insert or ignore into scan (scan_time, args) VALUES (?, ?) """
		self.cursor.execute(sql_statement, (time_of_scan, args))

	def insert_host_into_db(self, addr, hostname, time_of_scan):
		""" insert a host into the database """
		sql_statement = """insert or ignore into hosts (addr, hostname, scan_time) VALUES (?, ?, ?) """
		self.cursor.execute(sql_statement, (addr, hostname, time_of_scan))

	def insert_port_into_db(self, addr, protocol, serv_d, time_of_scan):
		""" insert a port into the database """
		sql_statement = """insert or ignore into open_port (addr, port, product, protocol, scan_time,
		name, servicefp, version) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"""
		self.cursor.execute(sql_statement, (addr, serv_d["portid"], serv_d["product"], \
			protocol, time_of_scan, serv_d["name"], serv_d["servicefp"], serv_d["version"] ))

	def insert_all_scan_info_into_db(self):
		"""
			XXX: make this method cleaner!
			insert every host that has open ports in the nmap xml file and
			a description for it (the port) into the database
		"""
		self._doc = etree.parse(self.filename)
		time_of_scan, args = "", ""
		for x in self._doc.xpath("//nmaprun"):
			time_of_scan = datetime.datetime.fromtimestamp(float(x.attrib['start']))
			args = x.attrib['args']

		self.insert_scan_into_db(time_of_scan, args)

		for x in self._doc.xpath("//host"):
			hostname = "" #this will be the value of the last hostname node's name element
			address = ""
			desc = ""
			protocol = ""
			for host_n in x.xpath("hostnames/hostname/@name"):
				hostname = host_n
			for addr in x.xpath("address/@addr[@addrtype!='mac']"):
				address = addr
			self.insert_host_into_db(address, hostname, time_of_scan)

			for open_p in x.xpath("ports/port[state[@state='open']]"):
				protocol = open_p.attrib['protocol']
				wrap_service_dict = self._service_wrap_attrib(list(open_p)[1].attrib)
				wrap_service_dict["portid"] = open_p.attrib["portid"]
				self.insert_port_into_db(address, protocol, wrap_service_dict, time_of_scan)

	def _service_wrap_attrib(self, child_attrib):
		""" some fields are optional - so enter a blank value for a key if it doesn't exist  """
		wrapped_dict_result = {}
		for key in ["version", "product", "name", "servicefp"]:
			if key in child_attrib.keys():
				wrapped_dict_result[key] = child_attrib[key]
			else:
				wrapped_dict_result[key] = ""
		return wrapped_dict_result

	def close_and_commit_to_db(self):
		""" commit to the database and close the cursor """
		self.conn.commit()
		self.cursor.close()

def main():
	filename = parse_opts()
	s = nmap_xml_to_sqlite(filename)
	s.create_store_dir()
	s.connect_to_db()
	s.create_db()
	s.insert_all_scan_info_into_db()
	s.close_and_commit_to_db()

if __name__ == "__main__":
	main()
