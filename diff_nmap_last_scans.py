#!/usr/bin/env python
from lxml import etree
import sqlite3
import os
import datetime
from shows_hosts_with_open_port_and_service_desc import parse_opts


__program__ = 'diff_nmap_last_scans'
___author__ = 'dave b. <db@d1b.org>'
__license__ = 'GPL v2'

class nmap_sqlite_query:
	def __init__(self, store_p=os.path.expanduser('~/.nmap_pdb/')):
		self.store_p = store_p
		self._db_name = "nmap.db"
		self.conn = None
		self.cursor = None

	def connect_to_db(self):
		""" connect to the database """
		self.conn = sqlite3.connect(self.store_p + self._db_name)
		self.cursor = self.conn.cursor()

	def close_and_commit_to_db(self):
		""" commit to the database and close the cursor """
		self.conn.commit()
		self.cursor.close()

	def query_db_diff(self, addr, args='%'):
		sql_query = "select strftime('%s', scan_time) from scan where args like ? order by scan_time desc limit 2 "
		self.cursor.execute(sql_query, (args,) )
		data = [row for row in  self.cursor]
		latest = str(data[1][0])
		previous = str(data[0][0])
		scan_result_latest = set(self.query_db_scan_results_for_time(latest))
		scan_result_previous = set(self.query_db_scan_results_for_time(previous))
		return (scan_result_latest.difference(scan_result_previous), scan_result_previous.difference(scan_result_latest))

	def query_db_scan_results_for_time(self, time):
		sql_query = "select addr, name, product, version from open_port where strftime('%s', scan_time)=?"
		self.cursor.execute(sql_query, (time,) )
		return  [row for row in self.cursor]

	def print_diff_of_scan(self, diff):
		for i in diff[0]:
			print "-", i
		for i in diff[1]:
			print "+", i

def main():
	s = nmap_sqlite_query()
	s.connect_to_db()
	diff = s.query_db_diff("1.%", "%-sV%")
	s.print_diff_of_scan(diff)
	s.close_and_commit_to_db()

if __name__ == "__main__":
	main()
