# Requirements

  * Python 2.7
  * Impacket Python library
  * sqlite3 Python library 

# sharecrawler
Python crawler for remote Windows shares

```
usage: pysharecrawler.py [-h] (--rhosts RHOSTS | --file FILE)
                         [--hashes HASHES] [--verbose] [--maxdepth MAXDEPTH]
                         [--out OUT]
                         LOGIN

Complete Windows Samba share crawler.

positional arguments:
  LOGIN                Can be standalone username for local account or
                       domain/username

optional arguments:
  -h, --help           show this help message and exit
  --rhosts RHOSTS      IP Adress or IP/CIDR
  --file FILE          Read IP adresses from input file. One adress per line
  --hashes HASHES      NTLM hashes, format is LMHASH:NTHASH
  --verbose            Show debug messages
  --maxdepth MAXDEPTH  Maximum depth to crawl in shares (default=1)
  --out OUT            Output type: (print, csv:<filepath>, sqlite:<dbpath>)
```

# shareanalyzer
Search patterns in files and directories in Windows samba shares

```
usage: pyshareanalyzer.py [-h] INPUT OUTPUT FILTERS

Windows Samba share analyzer.

positional arguments:
  INPUT       Input type: (csv:<filepath>, sqlite:<dbpath>)
  OUTPUT      Output type: (print, csv:<csvpath>, sqlite:<dbpath>,
              html:<htmlpath>)
  FILTERS     Path of file containing filtering regexes, one per line

optional arguments:
  -h, --help  show this help message and exit
```
