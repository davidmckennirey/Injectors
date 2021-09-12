import argparse
from os import X_OK
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
from base64 import b64decode
import codecs
import binascii

verbose = False
debug = False

def v(msg):
    if verbose:
        print(f"[*] {msg}")

def d(msg):
    if debug:
        print(f"[DEBUG] {msg}")

def cli():
    global verbose
    global debug
    parser = argparse.ArgumentParser()
    inp = parser.add_mutually_exclusive_group(required=True)
    inp.add_argument("-r", "--raw", help="Input shellcode as raw binary file", type=str)
    inp.add_argument("-b", "--base64-string", help="Input shellcode as base64 string", type=str)
    inp.add_argument("-bf", "--base64-file", help="Input shellcode as base64 file", type=str)
    inp.add_argument("-H", "--hex-string", help="Input shellcode as hex string", type=str)
    inp.add_argument("-Hf", "--hex-file", help="Input shellcode as hex file", type=str)
    parser.add_argument("-f", "--format", help="Output format for the shellcode. Options: raw or csharp (Default csharp)", type=str, choices=["raw", "csharp"], default="csharp")
    parser.add_argument("-o", "--output", help="Write the output to a file", type=str, default="")
    parser.add_argument("-e", "--encryption", help="Encryption format to use. Options: xor or aes (Default aes)", type=str, choices=["xor", "aes"], default="aes")
    parser.add_argument("-k", "--key", help="Key to encrypt the data with in ASCII hex format. (Default: Random 16 bytes)", type=str, default="")
    parser.add_argument("-v", "--verbose", help="Enable verbose output", action="store_true", default=False)
    parser.add_argument("--debug", help="Enable debug log", action='store_true', default=False)
    args = parser.parse_args()
    verbose = args.verbose
    debug = args.debug
    return args

def get_data(args):
    if args.base64_string:
        try:
            return b64decode(args.base64_string, validate=True)
        except binascii.Error as e:
            print("[!] ERROR: Shellcode was not provided in base64 format, exiting...")
            exit(-1)
    elif args.base64_file:
        try:
            with open(args.base64_file) as f:
                try:
                    return b64decode(f.read(), validate=True)
                except binascii.Error as e:
                    print("[!] ERROR: Shellcode was not provided in base64 format, exiting...")
                    exit(-1)
        except FileNotFoundError:
            print(f"[!] ERROR: Could not find shellcode file \"{args.base64_file}\", exiting...")
            exit(-1)
    elif args.hex_string:
        try:
            return bytes.fromhex(args.hex_string)
        except ValueError as e:
            print("[!] ERROR: Shellcode was not provided in hex format, exiting...")
            exit(-1)
    elif args.hex_file:
        try:
            with open(args.hex_file) as f:
                try:
                    return bytes.fromhex(f.read())
                except ValueError as e:
                    print("[!] ERROR: Shellcode was not provided in hex format, exiting...")
                    exit(-1)
        except FileNotFoundError:
            print(f"[!] ERROR: Could not find shellcode file \"{args.hex_file}\", exiting...")
            exit(-1)
    else: # Raw format
        try:
            with open(args.raw, "rb") as f:
                return f.read()
        except FileNotFoundError:
            print(f"[!] ERROR: Could not find shellcode file \"{args.raw}\", exiting...")
            exit(-1)

def aes_encrypt(data, key):
    # https://pycryptodome.readthedocs.io/en/latest/src/examples.html
    # AES.block_size = 16 bytes
    # Have to use CBC because its all that .NET supports
    iv = get_random_bytes(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size)), iv

def aes_decrypt(data, key, iv):
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), AES.block_size)

def get_csharp_array(ciphertext, name):
    array = ""
    i = 0
    while i < len(ciphertext):
        if i % 16 == 0 and i != 0:
            array += "\n"
        array += f"{ciphertext[i]:#0{4}x}"
        if i + 1 != len(ciphertext):
            array += ","
        i += 1
    return f"byte[] {name} = new byte[{len(ciphertext)}] {{\n{array} }};"

def main():
    args = cli()

    # Get the key either by decoding it or generating it
    if args.key:
        try:
            v(f"Reading key from CLI argument: {args.key}")
            key = bytes.fromhex(args.key)
        except ValueError as e:
            print("[!] ERROR: Provided key was not in hex format, exiting...")
            exit(-1)
    else:
        v(f"No key provided, generating...")
        key = get_random_bytes(16)

    # If AES was suppllied as encryption scheme, then the key must be 16 bytes long
    if args.key and args.encryption == "aes" and len(key) != 16:
        print(f"[!] ERROR: AES Encryption chosen, but key length is not equal to 16 bytes (Length: {len(key)}), exiting...")
        exit(-1)

    # Decode the data from whatever format was supplied
    v("Reading input shellcode...")
    data = get_data(args)
    v(f"Read {len(data)} bytes of shellcode from input!")

    # Encrypt the data using perferred encryption method
    if args.encryption == "aes":
            v("Encrypting shellcode using AES encryption...")
            ciphertext, iv = aes_encrypt(data, key)
    elif args.encryption == "xor":
        v("Encrypting shellcode using XOR 'encryption'...")
        ciphertext = "" # TODO
    v("Succesfully encrypted shellcode!")

    # Construct the output from the encrypted shellcode
    if args.format == "csharp":
        out = get_csharp_array(ciphertext, "buf")
        d(f'DECRYPTED SHELLCODE: {get_csharp_array(aes_decrypt(ciphertext, key, iv), "buf")}')
    elif args.format == "raw":
        out = data # We will just directly write bytes to a file

    # Output the encrypted shellcode in the specified format (file or stdout)
    if args.output:
        if args.format == "raw":
            with open(args.output, "wb") as f:
                f.write(out)
        elif args.format == "csharp":
            with open(args.output, "w") as f:
                f.write(out)
    else:
        print(out)

    # Print out the key in the same format as the shellcode
    if args.format == "csharp":
        print(get_csharp_array(key, 'key'))
    elif args.format == "raw": # Print out the key in hex
        print(f"KEY: {key.hex()}")

    # Lastly, if AES enc was chosen, print out the IV
    if args.encryption == "aes":
        if args.format == "csharp":
            print(f"{get_csharp_array(iv, 'iv')}")
        elif args.format == "raw":
            print(f"IV: {iv.hex()}")

if __name__ == "__main__":
    main()