"""
Michael Molho 
2015
michael.molho@gmail.com
"""

import os
import os.path
import sqlite3

class CsvOutWriter():
    def __init__(self, filepath): 
        self.filepath = filepath

    def write(self, host, share, fileattrs, filepath):
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
            self.cur.execute("CREATE TABLE Entries(Type TEXT, Host TEXT, Share TEXT, Filepath TEXT)")

    def write(self, host, share, fileattrs, filepath):
        if not fileattrs['directory']:
            query = "INSERT INTO Entries VALUES(?, ?, ?, ?)"
            self.cur.execute( query, ("F".encode('utf-8'), host.encode('utf-8'), share.encode('utf-8'), filepath) )
        else:
            query = "INSERT INTO Entries VALUES(?, ?, ?, ?)"
            self.cur.execute( query, ("D".encode('utf-8'), host.encode('utf-8'), share.encode('utf-8'), filepath) )

    def commit(self):
        self.dbconn.commit()



class StandardOutWriter():
    def commit(self):
        pass

    def write(self, host, share, fileattrs, filepath):
        if not fileattrs['directory']:
            print u"  [*] -F- ".encode('utf-8') + host.encode('utf-8') + u'\\'.encode('utf-8') + share.encode('utf-8') + filepath
        else:
            print u"  [*] -D- ".encode('utf-8') + host.encode('utf-8') + u'\\'.encode('utf-8') + share.encode('utf-8') + filepath
