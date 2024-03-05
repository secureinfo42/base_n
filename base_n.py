#!/usr/bin/env python3
#coding: utf-8



###################################################################################################
#
# Libs
#
##

import binascii
from getopt import getopt
from os import popen,system,unlink,remove
from sys import argv, stdin, stdout, exit
import colorama

import base64 # base16, base32, base85
import base36
import base45
import base58
import base62
import base91
import base92
from base128 import base128
import base256
BASE2048_ENABLED=1
try:
  import base2048
except:
  BASE2048_ENABLED=0
  pass
import base65536
import base114514

APP=argv[0].split("/")[-1]
C_GREEN = colorama.Fore.GREEN
C_RED   = colorama.Fore.RED
C_RESET = colorama.Fore.RESET
OK=C_GREEN + "✓" + C_RESET
KO=C_RED   + "✘" + C_RESET
VERBOSE = 0 # Show hexa dump when bruteforce


###################################################################################################
#
# Static version : including function basenc()
#
##

# 62 excluded because decode only integer
BASES = ["16","32","45","58","64","85","128","256","2048","65536","114514"]
# BASES = ["16","32","45","62","64","85","128","256","2048","65536","114514"]

EXEMPLES="""
Exemples :
----------

r = basenc("Hello")                   # base 64
r = basenc(b'SGVsbG8=',op="-d")

r = basenc("Hello","32")              # base 32
r = basenc(b'JBSWY3DP',"32","-d")

r = basenc("Hello","16")              # base 16
r = basenc(b'48656c6c6f',"16","-d")

r = basenc(1234,"36")                 # base 36
r = basenc('ya',"36","-d") 

r = basenc(b"Hello","45")             # base 45
r = basenc(b'%69 VDL2',"45","-d") 

r = basenc(101213,"62")               # base 62
r = basenc('qkt',"62","-d") 

r = basenc(b"Hello","85")             # base 85
r = basenc(b'NM&qnZv',"85","-d") 

r = basenc(b"Hello","91")             # base 91
r = basenc(">OwJh>A","91","-d") 

r = basenc(b"Hello","92")             # base 92
r = basenc(";K_$aOPi","92","-d") 

r = basenc(b"Hello ca va","128")      # base 128
# [b'$\\x19-Fc<@c', b'0H\\x0ef\\x01', [4]]
r = basenc(r,"128","-d") 

r = basenc(b"Hello","256")            # base 256
r = basenc('ňťŬŬůĊ',"256","-d") 

r = basenc(b"Hello","65536")          # base 65535
r = basenc("驈ꍬᕯ","65536","-d") 

r = basenc(b"Hello","base114514")          # base 114514
r = basenc("15545114154555154145511455444511","base114514","-d") 
"""

def basenc(data,base="64",op="-e"):

  try: data = data.encode()
  except: pass

  ### Base16 ##########################################################################################################

  if base == "16":

    if op == "-e": return( base64.b16encode(data).lower() )
    else: return( base64.b16decode(data.upper()) )

  ### Base32 ##########################################################################################################

  if base == "32":

    if op == "-e": return( base64.b32encode(data) )
    else: return( base64.b32decode(data) )

  ### Base36 ##########################################################################################################

  if base == "36":

    if op == "-e": return( str(base36.loads(data)) )
    else: return( base36.dumps(int(data)) )

  ### Base45 ##########################################################################################################

  if base == "45":

    if op == "-e": return( base45.b45encode(data) )
    else: return( base45.b45decode(data) )

  ### Base58 ##########################################################################################################

  if base == "58":

    if op == "-e": return( base58.b58encode(data) )
    else: return( base58.b58decode(data) )

  ### Base62 ##########################################################################################################

  if base == "62":
    if op == "-e":
      if type(data) is not int:
        try:
          data = int(data)
        except:
          raise Exception("Fatal: input data must be integer.")
        return(base62.encode(data))
      else:
        return(base62.encode(data))
    else:
      dec = str(base62.decode(data.decode()))
      return(dec)

  ### Base64 ##########################################################################################################

  if base == "64":

    if op == "-e": return( base64.b64encode(data) )
    else: return( base64.b64decode(data) )

  ### Base85 ##########################################################################################################

  if base == "85":

    if op == "-e": return( base64.b85encode(data) );
    else: return( base64.b85decode(data) )

  ### Base91 ##########################################################################################################

  if base == "91":

    if op == "-e": return( base91.encode(data) );
    else: return( base91.decode(data.decode()) )

  ### Base92 ##########################################################################################################

  if base == "92":

    if op == "-e": return( base92.encode(data) );
    else: return( base92.decode(data.decode()) )

  ### Base128 #########################################################################################################

  if base == "128":
    b128 = base128()

    if op == "-e":
      ret  = list(b128.encode(data))
      encoded = []
      for i in ret[:-1]:
        hex = binascii.hexlify(i).decode()
        encoded.append(hex)
      encoded.append(ret[-1])
      return(encoded)

    if op == "-d":
      decoded = ""
      try:
        data = data.strip().decode()
        offs = data.split(',')[-1].split('[')[1].split(']')[0]
        data = [ x[2:-1] for x in data.split(',')[:-1] ]
        data = [ binascii.unhexlify(x) for x in data ]
        data += [[int(offs)]]
        ret  = b128.decode(data)
        decoded = b''.join(list(ret))
      except:
        pass
      return(decoded)

  ### Base65536 #######################################################################################################

  if base == "256":
    tmpfile = "/tmp/.base256"
    # print(data,type(data))
    if op == "-e": 
      open(tmpfile,"wb").write(data)
      buff = base256.encode_file(tmpfile)
    else:
      base256.decode_file(data.decode(),tmpfile)
      buff = open(tmpfile,"r").read()
    remove(tmpfile)
    return(buff)

  ### Base2048 ########################################################################################################

  if base == "2048":
    if BASE2048_ENABLED:
      if op == "-e": return( base2048.encode(data) );
      else: return( base2048.decode(data.decode()) )

  ### Base65536 #######################################################################################################

  if base == "65536":

    if op == "-e": return( base65536.encode(data) );
    else: return( base65536.decode(data.decode()) )

  ### Base114514 ######################################################################################################

  if base == "114514":

    if op == "-e": return( base114514.b114514encode(data) );
    else: return( base114514.b114514decode(data.decode()) )




###################################################################################################
#
# Usage
#
##

def exemples():
  print(EXEMPLES)
  exit(0)

def usage(err):
  if err:
    if err == 2:
      error("no base specified\n")
    if err == 3:
      error("no operation specified\n")
    exit()


  msg ="""
Usage:

  %s <-H|-h> | <-b base> <-d|-r|-e> <-f file|->

  -b # : base number : 16, 32, 45, 58, 62, 64, 85, 91, 92, 128, 256, 2048, 65536, 114514
  -d   : decode
  -r   : bruteforce decode (try all base)
  -e   : encode
  -l   : list base (62 is excluded since mechanism is different)

Notes:

  base 62  : need integer as input
  base 128 : encoding returns array : [ encoded_data , [modulus] ]


Exemples:

  # Encode file '/bin/ls' to output
  %s /bin/ls

  # Encode stdin from /bin/ls
  cat /bin/ls|%s

  # Compute hash of stdin (can use `heredoc`)
  %s

  # Encode string
  printf 'myPasswordisverylongandsecret'|%s

  # Base62 test (decode string, encode integer)
  echo test|%s -b 62 -d|%s -b 62
"""

  print(msg % (APP,APP,APP,APP,APP,APP,APP) )
  exit(err)

#--------------------------------------------------------------------------------------------------

def file_exists(filename):
  try:
    open(filename,"rb").close()
    return(True)
  except:
    return(False)

#--------------------------------------------------------------------------------------------------

def debug(txt):
  open("/dev/stderr","wt").write("Debug: {}\n".format(txt))

#--------------------------------------------------------------------------------------------------

def my_print(txt):
  print(str(txt)[2:-1]) # b'bZ>NTbZ>NYZwd' -> bZ>NTbZ>NYZwd

#--------------------------------------------------------------------------------------------------

def read_stdin():
  ret = stdin.buffer.read()
  return(ret)

#--------------------------------------------------------------------------------------------------

def error(txt,errcode=0):
  msg = "{}: error: {}".format(APP,txt)
  open("/dev/stderr","wt").write(msg)
  if( errcode ):
    exit(errcode)

#--------------------------------------------------------------------------------------------------

def hexdump(data):
  tmpf = "/tmp/_base_n.tmp"
  open(tmpf,"wb").write(data)
  ret = popen("xxd -- '{}'|head".format(tmpf)).read()
  unlink(tmpf)
  return(ret)

#--------------------------------------------------------------------------------------------------

def read_file(filename):
  ret = ''
  try: ret = open(filename,'rb').read()
  except: error('unable to read file.\n',1)
  return(ret)



###################################################################################################
#
# Argments parsing
#
##

item      = ""
arg_index = 1
op        = "encode"
in_type   = "stdin"
arg_index = 1
data      = None

#--------------------------------------------------------------------------------------------------

base, args, op = "", "", ""

if len(argv[1:]) >= 6: usage(1)

for idx in range(len(argv[1:])+1):
  try:
    if argv[idx] == '-b': base = argv[idx+1]
    if argv[idx] == '-e': op = 'encode'
    if argv[idx] == '-d': op = 'decode'
    if argv[idx] == '-r': op = 'brute'
    if argv[idx] == '-l': op = 'list' ; data="-"
    if argv[idx] == '-h': usage(0)
    if argv[idx] == '-H': exemples()
    if argv[idx] == '-v': VERBOSE=1
    if argv[idx] == '-f': data = read_file(argv[idx+1])
  except:
    usage(1)

if not base: base='64'
if not op:   op='encode'
if not data: data = read_stdin()



###################################################################################################
#
# Operations
#
##

#--- Input data -----------------------------------------------------------------------------------

if op == "encode":
  out = basenc(data,base,"-e")
  # if type(out) is str:
  try:
    out = out.decode()
  except:
    pass
  print(out)
  # stdout.buffer.write(out)

if op == "decode":
  try:
    out = basenc(data,base,"-d")
  except ValueError:
    try:
      out = basenc(data.strip(),base,"-d")
    except:
      print("Invalid character in input stream.")
      exit(65) # like base64
  if type(out) is str:
    out = out.encode()
  if out:
    stdout.buffer.write(out)

if op == "list":
  print( ' '.join(BASES))

if op == "brute":
  print("")
  out = ""
  for base in BASES:

    ok = 0
    try:
      out = basenc(data,base,"-d")
      ok  = 1
    except ValueError:
      try:
        out = basenc(data.strip(),base,"-d")
        ok  = 1
      except:
        print("[ {} ] base%-6s : {}FAILED{}".format(KO,C_RED,C_RESET) % base)
        pass

    if ok == 1:
      try:
        if len(out) > 2:
          if VERBOSE == 1:
            print("")
          print("[ {} ] base%-6s : {}PASSED{}".format(OK,C_GREEN,C_RESET) % base)
          if VERBOSE == 1:
            print("-----------------")
            print("{}".format(hexdump(out)))
        else:
          print("[ {} ] base%-6s : {}FAILED{}".format(KO,C_RED,C_RESET) % base)
      except:
        print("[ {} ] base%-6s : {}FAILED{}".format(KO,C_RED,C_RESET) % base)
        pass


