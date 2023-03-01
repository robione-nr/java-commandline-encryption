# Java - Commandline Encryption Utility
Java program with a Linux commandline-like interface to encrypt and decrypt files.

I have a small personal interest in encryption and digital security. I don't have my Linux file systems encrypted but wanted the option of encrypting sensitive files on disk and decrypting them to stdout or a file on a ramdisk. That's how I personally use this. With the use of an alias the look and feel is that of any other Linux-based command line utility.

Java is not familiar to me

#### Features:
 - Password based key derivation
 - AES-256 GCM cipher
 - Unique IV and salt on each encryption
 
 #### Upcoming:
  - Streams for better memory usage
  - GZip to (un)compress plaintext
  - Multiple ciphers
  
 #### Usage:
    // Aliased as: 'alias encrypt "java -jar aes256gcm -e "'
    //             'alias decrypt "java -jar aes256gcm -d "'
    
    encrypt [-v] -i <input-file> [-o <output-file>] [-s <integer>]
    
    -v: Version info
    -i: Mandatory. Input file to encrypt or decrypt
    -o: Output file of the above operation. Defaults to stdout.
    -s: Salt size. Defaults to 100 bytes.
