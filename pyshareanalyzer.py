#!/usr/bin/python

import sqlite3
import argparse
import sys
import sqlite3
import time
from impacket import smb
from outwriter import CsvOutWriter, SqliteOutWriter, StandardOutWriter

class SmbAnalyzer():    
    def __init__(self, input, filters, out="print"):
        self.input = input
        self.out = out
        self.outwriter = StandardOutWriter()

        if len(input) > 7 and input[0:7] == "sqlite:": 
            self.filepath = input.split(':')[1]
            self.func_getvalue = self.sqlite_getvalue

        self.filters = [line.strip() for line in open(filters, 'r').readlines() if line[0] != '#']


    def analyze(self):
        for val in self.func_getvalue():
            host = val[0]
            nbtname = val[1]
            attributes = val[2]
            mtime = val[3]
            size = val[4]
            share = val[5]
            filepath = val[6]
            filename = filepath.replace('\\', '/').split('/')[-1]
            smbfile = smb.SharedFile(int(time.time()), int(time.time()), int(mtime), int(size), int(size), int(attributes), filename, filename)
            for filter in self.filters:
                if filter.lower() in filepath.lower():
                    self.outwriter.write(host, nbtname, share, smbfile, filepath)
        

    def sqlite_getvalue(self):
        self.dbconn = sqlite3.connect(self.filepath)
        self.cur = self.dbconn.cursor()    
        self.cur.execute("SELECT * FROM Entries")
        for row in self.cur.fetchall():
            yield row

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Windows Samba share analyzer.')
    parser.add_argument('INPUT', action="store", help="Input type: (csv:<filepath>, sqlite:<dbpath>)")
    parser.add_argument('OUTPUT', action="store", help="Output type: (print, csv:<csvpath>, sqlite:<dbpath>, html:<htmlpath>)")
    parser.add_argument('FILTERS', action="store", help="Path of file containing filtering regexes, one per line")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    result = parser.parse_args()
    cmdargs = dict(result._get_kwargs())

    analyzer = SmbAnalyzer(cmdargs['INPUT'], cmdargs['FILTERS'], cmdargs['OUTPUT'])
    analyzer.analyze()
    


