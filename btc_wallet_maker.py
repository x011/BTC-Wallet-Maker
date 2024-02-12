import json
import base64
import sys
from mnemonic import Mnemonic
import os
import gc
from getpass import getpass
from embit import bip32, bip39, script
from embit.networks import NETWORKS
from embit.ec import PrivateKey
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.exceptions import InvalidSignature
from collections import OrderedDict
import argparse
import base58
import hashlib
import qrcode
from PIL import Image, ImageDraw, ImageFont

# Check Pillow version for compatibility
if hasattr(Image, 'ANTIALIAS'):
    resample_filter = Image.ANTIALIAS
else:
    resample_filter = Image.Resampling.LANCZOS

# Predefined keys from the provided dictionary
wallet_keys = [
    "mnemonic", "testnet", "public_key_hex", "private_key_hex", "private_key_wif",
    "bip38_encrypted_key", "legacy_address", "segwit_address", "nested_segwit_address",
    "taproot_address", "legacy_derivation_path", "legacy_xpub", "legacy_xprv",
    "segwit_derivation_path", "segwit_xpub", "segwit_xprv", "nested_segwit_derivation_path",
    "nested_segwit_xpub", "nested_segwit_xprv", "taproot_derivation_path",
    "taproot_xpub", "taproot_xprv", "addresses_legacy", "addresses_segwit", "addresses_nested_segwit", "addresses_taproot"
]

# Function to resolve the wallet file path
def resolve_wallet_path(wallet_path):
    """ Resolve the wallet file path, handling both absolute and relative paths """
    # If the path is relative, it is interpreted as relative to the current working directory
    # If the path is absolute, it is returned as is
    return os.path.abspath(wallet_path)

# Function to generate and save QR code for an address
def gen_qrcode(wallet_type, address, filename, logo_path='btc-logo.png', font_path='Roboto-Medium.ttf', box_size=10):
        # Determine if we are running in a bundle or a script
    if getattr(sys, 'frozen', False):
        # If the application is run as a bundle, the pyInstaller bootloader
        # extends the sys module by a flag frozen=True and sets the app 
        # path into variable _MEIPASS'.
        application_path = sys._MEIPASS
    else:
        application_path = os.path.dirname(os.path.abspath(__file__))

    # Construct paths to the logo and font
    logo_path = os.path.join(application_path, logo_path)
    font_path = os.path.join(application_path, font_path)
    
    # Generate QR code
    qr = qrcode.QRCode(
        version=None,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=box_size,
        border=4,
    )
    qr.add_data(address)
    qr.make(fit=True)
    qr_img = qr.make_image(fill_color="black", back_color="white").convert('RGB')

    # Load the BTC logo and calculate its position
    logo = Image.open(logo_path)
    logo_size = qr_img.size[0] // 4
    logo = logo.resize((logo_size, logo_size), resample_filter)
    logo_pos = ((qr_img.size[0] - logo_size) // 2, (qr_img.size[1] - logo_size) // 2)

    # Embed the BTC logo into the QR code
    qr_img.paste(logo, logo_pos, mask=logo)

    # Load the TTF font
    font_size = qr_img.size[0] // 10
    font = ImageFont.truetype(font_path, font_size)

    # Prepare to add text
    text = wallet_type
    draw = ImageDraw.Draw(qr_img)

    # Get text size
    text_bbox = draw.textbbox((0, 0), text, font=font)
    text_width = text_bbox[2] - text_bbox[0]
    text_height = text_bbox[3] - text_bbox[1]

    # Calculate total height needed for text and QR code
    total_height = qr_img.size[1] + text_height + 20

    # Create an image with space for text
    combined_img = Image.new("RGB", (qr_img.size[0], total_height), color="white")

    # Add text
    text_x = (qr_img.size[0] - text_width) // 2
    text_y = 10
    draw = ImageDraw.Draw(combined_img)
    draw.text((text_x, text_y), text, font=font, fill="black")

    # Paste the QR code below the text
    qr_y = text_y + text_height + 10
    combined_img.paste(qr_img, (0, qr_y))

    # Save the image
    combined_img.save(filename)


def xor(a, b):
    return bytes(i ^ j for i, j in zip(a, b))

def bip38_encrypt(ec_private_key, passphrase, address, compressed=True):
    addresshash = hashlib.sha256(hashlib.sha256(address.encode('utf-8')).digest()).digest()[:4]
    scrypt_kdf = Scrypt(salt=addresshash, length=64, n=16384, r=8, p=8, backend=default_backend())
    derived = scrypt_kdf.derive(passphrase)
    derivedhalf1 = derived[:32]
    derivedhalf2 = derived[32:]
    aes_cipher = Cipher(algorithms.AES(derivedhalf2), modes.ECB(), backend=default_backend())
    aes_encryptor = aes_cipher.encryptor()
    privkey_bytes = ec_private_key.secret  # Use the secret as is, since it's already a bytes object
    encryptedhalf1 = aes_encryptor.update(xor(privkey_bytes[:16], derivedhalf1[:16]))
    aes_encryptor = aes_cipher.encryptor()  # Reinitialize the encryptor for the second half
    encryptedhalf2 = aes_encryptor.update(xor(privkey_bytes[16:], derivedhalf1[16:]))
    if compressed:
        flagbyte = b'\xe0'
    else:
        flagbyte = b'\xc0'
    encrypted_privkey = b'\x01\x42' + flagbyte + addresshash + encryptedhalf1 + encryptedhalf2
    encrypted_privkey += hashlib.sha256(hashlib.sha256(encrypted_privkey).digest()).digest()[:4]
    return base58.b58encode(encrypted_privkey).decode('utf-8')

# Function to prompt for password confirmation
def get_confirmed_password(prompt="Secure password to encrypt wallet: "):
    while True:
        password = getpass(prompt).encode()
        confirm_password = getpass("Confirm your password: ").encode()
        if password == confirm_password:
            return password
        else:
            print("Passwords do not match. Please try again.")


# Query available languages from the Mnemonic class
available_languages = Mnemonic.list_languages()

# Create the parser
parser = argparse.ArgumentParser(description='BTC Wallet Management Tool')

# Add main options
subparsers = parser.add_subparsers(dest='action', help='Create a new wallet or import an existing one')

# New wallet parser
new_parser = subparsers.add_parser('new', help='Create a new BTC wallet')
new_parser.add_argument('-t', '--testnet', action='store_true', help='Use testnet (default: False)')
new_parser.add_argument('-w', '--wallet_name', help='Specify the wallet name (default: legacy address with .wallet extension)')
new_parser.add_argument('-c', '--create', type=int, help='Create a specified number of extra addresses')
new_parser.add_argument('-p', '--password', nargs='?', const=True, help='Password to encrypt the wallet. Optional, will be asked if not provided')
new_parser.add_argument('-m', '--mnemonic_size', type=int, choices=[128, 160, 192, 224, 256], help='Specify the mnemonic size (default: 256)')
new_parser.add_argument('-l', '--language', choices=available_languages, default='english', help='Language for mnemonic generation (default: english)')
new_parser.add_argument('-o', '--overwrite', action='store_true', help='Overwrite the wallet file if it exists (default: False)')
new_parser.add_argument('-q', '--generate_qr', action='store_true', help='Generate QR codes for addresses (default: False)')


# Import wallet parser
import_parser = subparsers.add_parser('import', help='Import an existing BTC wallet using a mnemonic')
import_parser.add_argument('-m', '--mnemonic', nargs='?', default=None, help='Mnemonic phrase for the wallet. Optional, will be asked if not provided')
import_parser.add_argument('-t', '--testnet', action='store_true', help='Use testnet (default: False)')
import_parser.add_argument('-w', '--wallet_name', help='Specify the wallet name (default: legacy address with .wallet extension)')
import_parser.add_argument('-c', '--create', type=int, help='Create a specified number of extra addresses')
import_parser.add_argument('-p', '--password', nargs='?', const=True, help='Password to encrypt the wallet. Optional, will be asked if not provided')
import_parser.add_argument('-l', '--language', choices=available_languages, default='english', help='Language for mnemonic (default: english)')
import_parser.add_argument('-o', '--overwrite', action='store_true', help='Overwrite the wallet file if it exists (default: False)')
import_parser.add_argument('-q', '--generate_qr', action='store_true', help='Generate QR codes for addresses (default: False)')


# Add 'view' wallet parser
view_parser = subparsers.add_parser('view', help='View wallet details')
view_parser.add_argument('-p', '--password', nargs='?', default=None, help='Password to decrypt the wallet. Optional, will be asked if not provided')
view_parser.add_argument('-w', '--wallet', nargs='?', default=None, help='Specify the wallet file name to decrypt. Optional, will be asked if not provided')
view_parser.add_argument('-k', '--key', choices=wallet_keys, help='Display a single value from the wallet by key')

# Parse the arguments
args = parser.parse_args()

# Check if no action is provided and print help
if args.action is None:
    parser.print_help()
    sys.exit(1)

# Handle new wallet creation action
if args.action == 'new':
    # Set the mnemonic size, default to 256 if not specified
    mnemonic_size = args.mnemonic_size if args.mnemonic_size else 256
    # Validate mnemonic size
    if mnemonic_size not in [128, 160, 192, 224, 256]:
        print("Invalid mnemonic size. Allowed sizes are 128, 160, 192, 224, or 256.")
        sys.exit(1)
    # Generate a new mnemonic phrase based on the specified size and language
    mnemo = Mnemonic(args.language)
    args.mnemonic = mnemo.generate(strength=mnemonic_size)
    # Convert mnemonic phrase to seed using the same Mnemonic instance
    seed = mnemo.to_seed(args.mnemonic)

# Handle import wallet action
elif args.action == 'import':
    if not args.mnemonic:
        # Prompt for the mnemonic if not provided
        args.mnemonic = getpass("Enter your mnemonic phrase: ")
    # Create Mnemonic instance with the specified language or default to English
    mnemo = Mnemonic(args.language)
    try:
        seed = mnemo.to_seed(args.mnemonic)
    except Exception as e:
        print(f"Error: {e}")
        print("There was an error converting the mnemonic to a seed. Please make sure you are using the correct language (-l or --language).")
        sys.exit(1)

# Handle wallet view action
elif args.action == 'view':
    if args.wallet:
        file_name = resolve_wallet_path(args.wallet)
    else:
        file_name = input("Enter the wallet file name: ")
        file_name = resolve_wallet_path(file_name) 
    if not os.path.exists(file_name):
        print("Error: The wallet file does not exist.")
        sys.exit(1)
    password = args.password.encode() if args.password else getpass("Enter wallet password: ").encode()
    with open(file_name, 'r') as file:
        combined_base64 = file.read()
    combined = base64.b64decode(combined_base64)
    salt = combined[:16]
    iv = combined[16:32]
    encrypted_data = combined[32:]
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=300000,
        backend=default_backend()
    )
    key = kdf.derive(password)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    try:
        decrypted_padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        decrypted_data = unpadder.update(decrypted_padded_data) + unpadder.finalize()
        wallet_data = json.loads(decrypted_data.decode())
        if args.key:
            if args.key in wallet_data:
                if isinstance(wallet_data[args.key], list):
                    print(args.key, json.dumps(wallet_data[args.key], indent=4, ensure_ascii=False))
                else:
                    print(f"{args.key}: {wallet_data[args.key]}")
            else:
                print(f"Error: Key '{args.key}' not found in the wallet data.")
        else:
            print(f"Wallet {args.wallet}:")
            print(json.dumps(wallet_data, indent=4, ensure_ascii=False))
    except (ValueError, InvalidSignature) as e:
        print("Decryption failed. The password may be incorrect, or the wallet file may be corrupted.")
        print("Error:", str(e))
    
    sys.exit(0)

# If a password is provided directly, use it; otherwise, call get_confirmed_password
args.password = args.password.encode() if isinstance(args.password, str) else get_confirmed_password()

# True = testnet, False = mainnet
testnet = args.testnet

# Define the coin type based on the network
coin_type = "1'" if testnet else "0'"

# Define network type
network = NETWORKS["test" if testnet else "main"]

# Use BIP32 to derive keys
root = bip32.HDKey.from_seed(seed, version=network["xprv"])

# Derivation paths
legacy_derivation_path = f"m/44'/{coin_type}/0'/0/0"
nested_segwit_derivation_path = f"m/49'/{coin_type}/0'/0/0"
segwit_derivation_path = f"m/49'/{coin_type}/0'/0/0"
taproot_derivation_path = f"m/86'/{coin_type}/0'/0/0"

# Derive legacy address (P2PKH)
legacy_key = root.derive(legacy_derivation_path)
legacy_address = script.p2pkh(legacy_key).address(network)


# Derive SegWit address (P2WPKH)
segwit_key = root.derive(segwit_derivation_path)
segwit_address = script.p2wpkh(segwit_key).address(network)


# Derive nested SegWit address (P2SH-P2WPKH)
nested_segwit_key = root.derive(nested_segwit_derivation_path)
nested_segwit_address = script.p2sh(script.p2wpkh(nested_segwit_key)).address(network)

# Derive Taproot address (P2TR)
taproot_key = root.derive(taproot_derivation_path)
taproot_scriptpubkey = script.p2tr(taproot_key)
taproot_address = taproot_scriptpubkey.address(network)

private_key = PrivateKey(legacy_key.secret)

# Set the network for the WIF (mainnet or testnet)
private_key.network = NETWORKS['main'] if not testnet else NETWORKS['test']

# Get the WIF format of the private key
private_key_wif = private_key.wif()

# Get the HEX format of the private key
private_key_hex = private_key.secret.hex()


# Generate BIP38 encrypted private key
bip38_encrypted_key = bip38_encrypt(private_key, args.password, legacy_address)

# Add nested SegWit address to the wallet details
wallet_details = OrderedDict({
    "mnemonic": args.mnemonic,
    "testnet": testnet,
    "public_key_hex": legacy_key.sec().hex(),
    "private_key_hex": private_key_hex,
    "private_key_wif": private_key_wif,
    "bip38_encrypted_key": bip38_encrypted_key,
    "legacy_address": legacy_address,
    "segwit_address": segwit_address,
    "nested_segwit_address": nested_segwit_address,  # Nested SegWit address
    "taproot_address": taproot_address,
    "legacy_derivation_path": legacy_derivation_path,
    "legacy_xpub": root.derive(f"m/44'/{coin_type}/0'").to_public().to_base58(),
    "legacy_xprv": root.derive(f"m/44'/{coin_type}/0'").to_base58(),
    "segwit_derivation_path": segwit_derivation_path,
    "segwit_xpub": root.derive(f"m/49'/{coin_type}/0'").to_public().to_base58(),
    "segwit_xprv": root.derive(f"m/49'/{coin_type}/0'").to_base58(),
    "nested_segwit_derivation_path": nested_segwit_derivation_path,  # Nested SegWit derivation path
    "nested_segwit_xpub": root.derive(f"m/49'/{coin_type}/0'").to_public().to_base58(),  # Nested SegWit xpub
    "nested_segwit_xprv": root.derive(f"m/49'/{coin_type}/0'").to_base58(),  # Nested SegWit xprv
    "taproot_derivation_path": taproot_derivation_path,
    "taproot_xpub": root.derive(f"m/86'/{coin_type}/0'").to_public().to_base58(),
    "taproot_xprv": root.derive(f"m/86'/{coin_type}/0'").to_base58(),
})


# Generate extra addresses if requested
if args.create and args.create > 0:
    extra_addresses = {
        "legacy": [],
        "segwit": [],
        "nested_segwit": [],
        "taproot": []
    }
    for i in range(1, args.create + 1):
        # Derive extra legacy addresses
        extra_legacy_key = root.derive(f"m/44'/{coin_type}/0'/0/{i}")
        extra_legacy_address = script.p2pkh(extra_legacy_key).address(network)
        extra_addresses["legacy"].append(extra_legacy_address)

        # Derive extra SegWit addresses
        extra_segwit_key = root.derive(f"m/84'/{coin_type}/0'/0/{i}")
        extra_segwit_address = script.p2wpkh(extra_segwit_key).address(network)
        extra_addresses["segwit"].append(extra_segwit_address)

        # Derive extra nested SegWit addresses
        extra_nested_segwit_key = root.derive(f"m/49'/{coin_type}/0'/0/{i}")
        extra_nested_segwit_address = script.p2sh(script.p2wpkh(extra_nested_segwit_key)).address(network)
        extra_addresses["nested_segwit"].append(extra_nested_segwit_address)

        # Derive extra Taproot addresses
        extra_taproot_key = root.derive(f"m/86'/{coin_type}/0'/0/{i}")
        extra_taproot_scriptpubkey = script.p2tr(extra_taproot_key)
        extra_taproot_address = extra_taproot_scriptpubkey.address(network)
        extra_addresses["taproot"].append(extra_taproot_address)

    wallet_details["addresses_legacy"] = extra_addresses["legacy"]
    wallet_details["addresses_segwit"] = extra_addresses["segwit"]
    wallet_details["addresses_nested_segwit"] = extra_addresses["nested_segwit"]
    wallet_details["addresses_taproot"] = extra_addresses["taproot"]


# Generate a random salt
salt = os.urandom(16)

# Use PBKDF2HMAC to derive a key from the password and salt
kdf = PBKDF2HMAC(
    algorithm=hashes.SHA512(),
    length=32,  # 32 bytes = 256 bits for AES-256
    salt=salt,
    iterations=300000,
    backend=default_backend()
)
key = kdf.derive(args.password)

# Create a cipher object using AES-256 and CBC mode
iv = os.urandom(16)  # Initialization vector for CBC mode
cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
encryptor = cipher.encryptor()

# Pad the data to be encrypted
padder = padding.PKCS7(algorithms.AES.block_size).padder()
padded_data = padder.update(json.dumps(wallet_details).encode()) + padder.finalize()

# Encrypt the data
encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

# Combine the salt, IV, and encrypted data
combined = salt + iv + encrypted_data

# Encode the combined data as base64
combined_base64 = base64.b64encode(combined)

# Define the wallet name and directory
wallet_name = args.wallet_name if args.wallet_name else f'{legacy_address}'
wallet_dir = resolve_wallet_path(wallet_name + '_wallet')  # Folder name for the wallet and QR codes

# Create the wallet directory if it does not exist
if not os.path.isdir(wallet_dir):
    os.makedirs(wallet_dir)

# Define the wallet file path
wallet_file_path = os.path.join(wallet_dir, wallet_name + '.wallet')

# Check if the wallet file exists and prompt the user if overwrite is not specified
if os.path.exists(wallet_file_path) and not args.overwrite:
    response = input(f"The file '{wallet_file_path}' already exists. Do you want to overwrite it? (y/N): ").strip().lower()
    if response != 'y':
        print("Operation cancelled by user.")
        sys.exit(1)

# Save the wallet file
with open(wallet_file_path, 'w') as file:
    file.write(combined_base64.decode('utf-8'))

print(json.dumps(wallet_details, indent=4, ensure_ascii=False))

# Check if QR code generation is requested
if args.generate_qr:
    # Generate and save QR codes for each address with the appropriate filenames
    gen_qrcode('Legacy', legacy_address, os.path.join(wallet_dir, f'legacy_{wallet_name}.png'), box_size=20)
    gen_qrcode('Nested SegWit', nested_segwit_address, os.path.join(wallet_dir, f'nested_segwit_{wallet_name}.png'), box_size=20)
    gen_qrcode('SegWit', segwit_address, os.path.join(wallet_dir, f'segwit_{wallet_name}.png'), box_size=20)
    gen_qrcode('Taproot', taproot_address, os.path.join(wallet_dir, f'taproot_{wallet_name}.png'), box_size=20)
    print(f"QR Codes have been generated for Legacy, Nested SegWit, SegWit and Taproot addresses.")

print(f"Wallet has been encrypted and saved to {wallet_file_path}.")

# Clean up sensitive variables
del mnemo 
del seed
del root
del legacy_key
del segwit_key
del nested_segwit_key
del taproot_key
del private_key
del private_key_hex
del private_key_wif
del bip38_encrypted_key
del wallet_details
del encrypted_data
del combined
del key
del cipher
del kdf
del salt
del args

# Force garbage collection...
gc.collect()
