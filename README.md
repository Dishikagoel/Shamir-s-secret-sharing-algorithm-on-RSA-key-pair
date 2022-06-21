# Shamirs-secret-sharing-algorithm-on-RSA-key-pair

**CLI Program:**
  
   This command line interface program creates an RSA key pair and shards (breaks up into pieces) the private key 
   into n pieces using Shamir's secret sharing algorithm so that when given atleast k pieces, the app  re-creates 
   the private key and is able to decrypt the message encrypted using the public key.

**Program Dependencies:**

   The program was built in python 3.9, and should be compatible with versions 3.6 and later.
   The libraries used are-

   1. cryptography can be intalled using 
   
           $ pip install cryptography
       
   2. sslib can be installed using 
   
           $ pip install sslib


**How to run on Command Line:**

   Use the following command to run the program on CLI-

    python3 rsa_sss.py

  The above command will prompt you to input the following:
  n - the number of shares you would like to split your RSA key into
  k - the minimum number of shares needed to reassemble the private key
  message - the message to encrypt
  indices - the indices of shards you would like to use to reassemble the private key (separate the values by ',')

  As you hit enter after inputting the last value requried, the program should run and do the following:
  1. write the public key to a text file called Public.TXT
  2. write the private key shards to text files called Shard[k].TXT
  3. print out the decrypted message

**Unit Test:**

   The unit test demonstrate that the program works correctly, by doing the following:

  1.	Creates the RSA key pairs with a Private Key broken into 5 shards.
  2.	Encrypts a random plain text string using the RSA Public Key.
  3.	Reassembles the Private Key using shard 2 & 5.
  4.	Decrypts the cypher text back into the plain text using the reassembled Private Key.
  5.	Asserts the decrypted plain text is equal to the original random plain text in Step 2.

**How to run the unit test:**

   The unit test uses an in-built python library `unittest`. To run the unit test use the following command:

    python3 unit_tests.py
