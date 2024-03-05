# base_n

Encode and decode in several encoding base.

## Install

`pip3 install -r requirements.txt`

## Synopsis

```
Usage:

  base_n <-H|-h> | <-b base> <-d|-r|-e> <-f file|->

  -b # : base number : 16, 32, 45, 62, 64, 85, 91, 92, 128, 256, 65536
  -d   : decode
  -r   : bruteforce decode (try all base)
  -e   : encode

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

  # Base62 test
  echo test|base_n -b 62 -d|base_n -b 62
```
