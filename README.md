# Dumpy

**`Dumpy`** is a tool I've created to extract hashes from previously encrypted SAM, LSA, and SECURITY files that were encrypted using the XOR algorithm. This tool saves me time by automating the process of decrypting and extracting the hashes.

 ```
 python .\Dumpy.py -h
usage: Dumpy.py [-h] [--output_file OUTPUT_FILE] sam_file system_file security_file key

Decrypt SAM, SYSTEM, and SECURITY files using XOR operation and extract password hashes.

positional arguments:
  sam_file              The path to the SAM file.
  system_file           The path to the SYSTEM file.
  security_file         The path to the SECURITY file.
  key                   The key for decryption.

options:
  -h, --help            show this help message and exit
  --output_file OUTPUT_FILE
                        The path to the output file to save the extracted hashes.
```
