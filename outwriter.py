"""
Michael Molho 
2015
michael.molho@gmail.com
"""

import os
import os.path
import sqlite3
import time
import datetime


def sizeof_fmt(num, suffix='B'):
    for unit in ['','Ki','Mi','Gi','Ti','Pi','Ei','Zi']:
        if abs(num) < 1024.0:
            return "%3.1f%s%s" % (num, unit, suffix)
        num /= 1024.0
    return "%.1f%s%s" % (num, 'Yi', suffix)


class CsvOutWriter():
    def __init__(self, filepath): 
        self.filepath = filepath

    def write(self, host, nbtname, share, fileattrs, filepath):
        pass

    def commit(self):
        pass



class SqliteOutWriter():
    def __init__(self, filepath):
        self.filepath = filepath
        if os.path.isfile(filepath):
            keepfile = raw_input("\nWARNING: The file " + filepath + " already exits. Would you like to keep the content and add new entries ? Otherwise the file will be erased. (y/N) ")
            if keepfile == "N":
                os.remove(filepath)
                self.initdb(False)
            elif keepfile == "y":
                self.initdb(True)
        else:
            self.initdb(False)

    def initdb(self, keepexisting):
        self.dbconn = sqlite3.connect(self.filepath)
        self.cur = self.dbconn.cursor()    
        if not keepexisting:
            self.cur.execute("CREATE TABLE Entries(Host TEXT, \
                                                   NbtName TEXT, \
                                                   Attributes INTEGER, \
                                                   Mtime INTEGER, \
                                                   Size INTEGER, \
                                                   Share TEXT, \
                                                   Filepath TEXT)")

    def write(self, host, nbtname, share, fileattrs, filepath):
        query = "INSERT INTO Entries VALUES(?, ?, ?, ?, ?, ?, ?)"
        data = ( host,
                 nbtname,
                 int(fileattrs.get_attributes()),
                 int(fileattrs.get_mtime_epoch()),
                 int(fileattrs.get_filesize()),
                 share,
                 filepath )
        self.cur.execute( query, data )

    def commit(self):
        self.dbconn.commit()



class StandardOutWriter():
    def commit(self):
        pass

    def write(self, host, nbtname, share, fileattrs, filepath):
        is_ro = 'R' if fileattrs.is_readonly() else '-'
        is_system = 'S' if fileattrs.is_system() else '-'
        is_hidden = 'H' if fileattrs.is_hidden() else '-'
        is_directory = 'D' if fileattrs.is_directory() else '-'
        attrs = "-".join([is_ro, is_system, is_hidden, is_directory])
        mtime = datetime.datetime.fromtimestamp(int(fileattrs.get_mtime_epoch())).strftime('%Y-%m-%d')
        ctime = datetime.datetime.fromtimestamp(int(fileattrs.get_ctime_epoch())).strftime('%Y-%m-%d')
        size = str(sizeof_fmt(fileattrs.get_filesize())).ljust(10)
        print u"  [*] ".encode('utf-8') + attrs.ljust(4) + '   ' + mtime + '   ' + size + '   ' + share.encode('utf-8') + filepath
