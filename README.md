# base_n

Encode and decode in several encoding base.

## Install

`pip3 install -r requirements.txt`

## Synopsis

```
Usage:

  base_n <-H|-h> | <-b base> <-d|-r|-e> <-f file|->

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
  base_n /bin/ls

  # Encode stdin from /bin/ls
  cat /bin/ls|base_n

  # Compute hash of stdin (can use `heredoc`)
  base_n

  # Encode string
  printf 'myPasswordisverylongandsecret'|base_n

  # Base62 test (decode string, encode integer)
  echo test|base_n -b 62 -d|base_n -b 62
```

## Test

### Bruteforce

`$ echo 'Hello'|base_n -b 2048|base_n -r -v`

Output : 

```

[ ✘ ] base16     : FAILED
[ ✘ ] base32     : FAILED
[ ✘ ] base45     : FAILED
[ ✘ ] base58     : FAILED
[ ✘ ] base64     : FAILED
[ ✘ ] base85     : FAILED
[ ✘ ] base128    : FAILED
[ ✘ ] base256    : FAILED

[ ✓ ] base2048   : PASSED
-----------------
00000000: 4865 6c6c 6f0a                           Hello.

[ ✘ ] base65536  : FAILED
[ ✘ ] base114514 : FAILED
```

### Regression test

$ echo 'Hello'|base_n -b 65536|base_n -b 65536 -d
Hello


$ echo 'Hello'|base_n -b 65536|base_n -b 65536 -d
Hello
