#!/usr/bin/python

"""
Michael Molho 
2015
michael.molho@gmail.com
"""

from impacket.dcerpc import srvsvc

import sys
import string
import time
import logging
from impacket import smb, version, smb3, nt_errors
from impacket.dcerpc.v5 import samr, transport, srvs
from impacket.dcerpc.v5.dtypes import NULL
from impacket.smbconnection import *
from impacket.nmb import NetBIOS
from getpass import getpass
import argparse
import ntpath
import netaddr
from outwriter import CsvOutWriter, SqliteOutWriter, StandardOutWriter


class SmbCrawler():    
    def __init__(self, verbose=False, out="print"):
        self.host = ''
        self.nbtname = ''
        self.smb = None
        self.maxdepth = 999
        self.password = None
        self.lmhash = None
        self.nthash = None
        self.username = ''
        self.domain = ''
        self.verbose = verbose

        if len(out) > 4 and out[0:4] == "csv:": 
            filepath = out.split(':')[1]
            self.outwriter = CsvOutWriter(filepath)
        elif len(out) > 7 and out[0:7] == "sqlite:": 
            filepath = out.split(':')[1]
            self.outwriter = SqliteOutWriter(filepath)
        else:
            self.outwriter = StandardOutWriter()

    def resolveNbtName(self):
        nbt = NetBIOS() 
        try:
           name = nbt.getnetbiosname(self.host) 
           return name
        except:
           return ''

    def open(self, host, port):
        self.host = host
        self.nbtname = self.resolveNbtName()
        if port == 139:
            self.smb = SMBConnection('*SMBSERVER', host, sess_port=port)
        else:
            self.smb = SMBConnection(host, host, sess_port=port)

        dialect = self.smb.getDialect()
        if dialect == SMB_DIALECT:
            logging.info("SMBv1 dialect used")
        elif dialect == SMB2_DIALECT_002:
            logging.info("SMBv2.0 dialect used")
        elif dialect == SMB2_DIALECT_21:
            logging.info("SMBv2.1 dialect used")
        else:
            logging.info("SMBv3.0 dialect used")

    def login(self, domain, username, password):
        if self.smb is None:
            logging.error("No connection open")
            return

        try:
            self.smb.login(username, password, domain=domain)
        except Exception as e:
            print ("Authentication failed : " + str(e))
            raise
        self.username = username
        self.domain = domain

        if self.smb.isGuestSession() > 0:
            logging.info("GUEST Session Granted")
        else:
            logging.info("USER Session Granted")

    def shares(self):
        shares = []
        rpctransport = transport.SMBTransport(self.smb.getRemoteHost(), self.smb.getRemoteHost(), filename = r'\srvsvc', smb_connection = self.smb)
        dce = rpctransport.get_dce_rpc()
        dce.connect()
        dce.bind(srvs.MSRPC_UUID_SRVS)
        res = srvs.hNetrShareEnum(dce,1)
        resp = res['InfoStruct']['ShareInfo']['Level1']['Buffer']
        for i in range(len(resp)):                        
            shares += [resp[i]['shi1_netname'][:-1]]
        return shares

    def ls(self, share, pwd):
        files = []
        f_pwd = ''
        f_pwd = ntpath.join(pwd, '*')
        f_pwd = string.replace(f_pwd,'/','\\')
        f_pwd = ntpath.normpath(f_pwd)
        for f in self.smb.listPath(share, f_pwd):
            tmp =  { 'directory': True if f.is_directory() else False,
                     'size' : f.get_filesize(),
                     'ctime': time.ctime(float(f.get_mtime_epoch())),
                     'shortname' : f.get_shortname(), 
                     'longname' : f.get_longname() }
            if tmp['longname'] not in ['.', '..']:
                files += [tmp]
        return files

    def use(self,share):
        tid = self.smb.connectTree(share)
        self.ls(share, '\\')
        return tid

    def spider(self, share, root, maxdepth):
        if maxdepth < 0:
            return []
        try:
            files = self.ls(share, root)
        except Exception as e:
            if self.verbose:
                print ("Error in ls("+share+","+root+","+str(maxdepth)+") : " + str(e))
            return []
        for f in files:
            new_root = ntpath.join(root, f['longname'])
            new_root = ntpath.normpath(new_root)
            self.outwriter.write(self.host, self.nbtname, share, f, new_root)
            if f['directory']:
                self.spider(share, root + f['longname'] + '\\', maxdepth - 1)

    def crawl(self, maxdepth, thread = 1):
        self.maxdepth = maxdepth
        shares = self.shares()
        for share in shares:
            print ('[+] Spidering ' + share)
            try:
                tid = self.use(share)
            except Exception as e:
                if self.verbose:
                    print ("Error in use("+share+") : " + str(e))
            self.spider(share, '\\', maxdepth)
            self.outwriter.commit()

if __name__ == "__main__":
    rhosts = []
    domain = ''
    username = ''

    parser = argparse.ArgumentParser(description='Complete Windows Samba share crawler.')
    parser.add_argument('LOGIN', action="store", help="Can be standalone username for local account or domain/username")
    usergroup = parser.add_mutually_exclusive_group(required=True)
    usergroup.add_argument('--rhosts', action="store", default=None, help="IP Adress or IP/CIDR")
    usergroup.add_argument('--file', action="store", default=None, help="Read IP adresses from input file. One adress per line")
    parser.add_argument('--verbose', action="store_true", default=False, help="Show debug messages")
    parser.add_argument('--maxdepth', action="store", type=int, default=1, help="Maximum depth to crawl in shares (default=1)")
    parser.add_argument('--out', action="store", default="print", help="Output type: (print, csv:<filepath>, sqlite:<dbpath>)")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)
    
    result = parser.parse_args()
    cmdargs = dict(result._get_kwargs())
    
    if cmdargs['file'] != None:
        rhosts += [line.strip() for line in open(cmdargs['file'], 'r')]
    else:
        rhosts += [ip.__str__() for ip in list(netaddr.IPNetwork(cmdargs['rhosts']))]
    if '/' in cmdargs['LOGIN']:
        domain, username = tuple(cmdargs['LOGIN'].split('/'))
    else:
        domain, username = '', cmdargs['LOGIN']
    password = getpass("Password:")

    crawler = SmbCrawler( verbose=cmdargs['verbose'], out=cmdargs['out'] )

    for rhost in rhosts:
        print ('\n -- ' + rhost + ' -- \n')
        try:
            crawler.open(rhost,445)
            crawler.login(domain, username, password)
            crawler.crawl(maxdepth = cmdargs['maxdepth'])
        except Exception as e:
            if crawler.verbose:
                print ("Error : " + str(e))
