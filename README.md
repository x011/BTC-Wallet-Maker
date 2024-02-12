# BTC Wallet Maker

## Overview

The BTC Wallet Maker is a specialized tool designed for the secure generation and retrieval of Bitcoin wallet details. It operates entirely offline, providing a secure environment for handling your wallet's sensitive information. Additionally, the tool supports various Bitcoin address types, allowing users to generate and manage addresses specific to their needs, including legacy, SegWit, Nested SegWit, and Taproot formats. This tool is ideal for users who prioritize the security of their wallet's keys and wish to avoid the risks associated with online wallet services. This versatility ensures that users can maintain compatibility with different Bitcoin transaction types and network preferences.

## Installation

Clone the repository and install the requirements:

```
git clone https://github.com/x011/BTC-Wallet-Maker.git
cd BTC-Wallet-Maker
pip install -r requirements.txt
```

## Download Precompiled Binaries

For added convenience, precompiled binaries for Windows, Linux and macOS are available for [download](https://github.com/x011/BTC-Wallet-Maker/releases/).

!Attention macOS users: Binary files may experience slow loading times as macOS performs cloud-based verification. For quicker execution, consider running the Python script instead.

## BTC Wallet Example:

```
"mnemonic": "blanket food mean shed frown violin badge jump ladder excuse upper course wet helmet galaxy dentist office afraid axis sand drink until owner express",
"testnet": false,
"public_key_hex": "02b29f55dd5361a42916c62cae3a9fa8e8d8eedc48623e854ea2c95a93c013df07",
"private_key_hex": "31bbd547bf7d8cabdbba7cabef43ed38f5acdeb58500bc06a45affe2d4179f77",
"private_key_wif": "KxtPPFJUUkYEQfSSw3erVDtKHqPgEY611E6LnUfp1sEWeEbKEMey",
"bip38_encrypted_key": "6PYRmZ8cZ8kPTsK9kyVTw1sR3ec9iKA5K2k6H1DP1B9GVoaZK58238Gdb6",
"legacy_address": "18UF9z8QX4FkP797Tb7RMo9upMiifFi5UB",
"segwit_address": "bc1qlwdcmphx94nnteesd9jekz4kp6gcpucn99w0dd",
"nested_segwit_address": "336cT7y3kZ51MBq3to3shzSmjCuBVPxxPo",
"taproot_address": "bc1prx7q2usat549etjx7fgn6fusfdy7neuu0wzdydcztv2gu4v3mqlsjepx8l",
"legacy_derivation_path": "m/44'/0'/0'/0/0",
"legacy_xpub": "xpub6DUuqPDtd8NWKyKbEj2jYyta5gskb8jumSde2BVut5pA7DdFcH7vtuGPXqthhBToHzy3B16BstGZy42sJMVVr2GM7vUyXMuEWSRubmuPUDQ",
"legacy_xprv": "xprv9zVZRsgznkpD7VF88hVjBqwqXf3GBg24QDi3Do6JKkHBERJ74jogM6wugbFAix2rMxCERbL7gDZ3jhh6BQmZ7K9bmwmRedLkJh6B2XWwvPV",
"segwit_derivation_path": "m/49'/0'/0'/0/0",
"segwit_xpub": "xpub6CTvTgC2bxy5dTc3aav1kUYSDhs9eZtVcJV1P5AYfXYdBgSr2ksaqg8w8FBjBSs3fFR5wLAqDxeKAHQuBJj7ZfjDfkyReDNcLZz34C6fAdu",
"segwit_xprv": "xprv9yUa4Af8mbQnQyXaUZP1PLbhfg2fF7AeF5ZQagkw7C1eJt7hVDZLHspTGyiKMVqVbLZjSWjtthDvtKrwELnBKWPEjAERkJSLarMeVkSy6jM",
"nested_segwit_derivation_path": "m/49'/0'/0'/0/0",
"nested_segwit_xpub": "xpub6CTvTgC2bxy5dTc3aav1kUYSDhs9eZtVcJV1P5AYfXYdBgSr2ksaqg8w8FBjBSs3fFR5wLAqDxeKAHQuBJj7ZfjDfkyReDNcLZz34C6fAdu",
"nested_segwit_xprv": "xprv9yUa4Af8mbQnQyXaUZP1PLbhfg2fF7AeF5ZQagkw7C1eJt7hVDZLHspTGyiKMVqVbLZjSWjtthDvtKrwELnBKWPEjAERkJSLarMeVkSy6jM",
"taproot_derivation_path": "m/86'/0'/0'/0/0",
"taproot_xpub": "xpub6Bh3KH7y1UkWqUb2JtUd999r29TrtABnQLvwUMQzU5qETHhnW1W5KBHkg2Rzh1XdcGV1g3t7TcG4oBKWqC1gdhfgoZCdDX2zUJ8Ta84aeFU",
"taproot_xprv": "xprv9xhgumb5B7CDczWZCrwcn1D7U7dNUhTw381Lfy1NukJFaVNdxUBpmNyGphzdvaibeYErjck2Qkmv9SB8oURq73SprQqoVyscLcAnf5HDUWF",
"addresses_legacy": [
    "1Nzu5sMNMopjbMjLESSRM5uByrirYCjgCr",
    "1DUMZDvFwXobPn7JWd7tJ5vLy1NcoUXAAz",
    "1PkMRMogbQMP3H3bJrYrUhrKuB85krg7v1",
    "1Cft1FEgB6quLpGtqYX9m6JngJjQmUYPE1",
    "1B6uzgBPEqSB8RLmzodFc3fEdqxidBG7sR"
],
"addresses_segwit": [
    "bc1qxktfpeg0h6qmect4wu3scfu904nx6735me83yd",
    "bc1que4z5hurjmajr5av4er6gpn4yrc95tl6g42xzp",
    "bc1qhptze630n2rumf0myt4cpxqzfq75cgp7jkdklr",
    "bc1qf3ruclqespdsn9xpkq4khhfwdxvfjfhfdxnmpd",
    "bc1qnhzdtkg76ny94dj7xp09f7knrakttwjan6gw0v"
],
"addresses_nested_segwit": [
    "3CEK4jRmExyrRMQ5oHPQbvMDQ4o524C1mY",
    "3JinYJy5iV3uWzA4nyFYyrdZTe6DmFa67a",
    "3KE6QnVAofCug6dsY7gp13RnHDw4HgwkRy",
    "3PNRaN6zaUAg3RWpau2jja5aLyvsVq8EMa",
    "36J1gppHT42oCTdXC7awWEavZyf5ac9xHD"
],
"addresses_taproot": [
    "bc1p7dl6htr27y8mtpalqr2lg47vr8eg98em4cepejsqmyxxaql5683qwrd78v",
    "bc1pmtpp0sydem5mzj0dxrp224sqyals6tvl537ma8skd2jfp6306kuqpr6k8m",
    "bc1pt3lw9j69yyuxxmy6hu8jmxwkq5w05f9gg997n9k34jkaw4t3nskqrrc49s",
    "bc1puve48pp6ud3cenvvt4u6lmy4vp69hqstzarnvmse2dzyc83rkrnqn04h0t",
    "bc1puy4rwwka5y63l7gfk56wm36ujzl6aexs9lrzfpu3x6vw3ggeu6psly7t43"
]
```

## Create a new Wallet

### Minimal Example

`python btc_wallet_maker.py new`

In this minimal example, the script will use the default options for all parameters and will prompt the user for any necessary information, such as what password to encrypt the wallet with. It will also generate a wallet with a 256-bit mnemonic in English, will not overwrite existing files without confirmation, and will not create extra addresses or generate QR codes unless specified by the user during the prompts.


### Using all arguments:

`python btc_wallet_maker.py new --testnet --wallet_name "mywallet" --create 5 --password "mysecurepassword" --mnemonic_size 256 --language english --overwrite --generate_qr`

or

`python btc_wallet_maker.py new -t -w "mywallet" -c 5 -p "mysecurepassword" -m 256 -l english -o -q`


### Explanation of each `new` argument:

- `new`: This is the action that tells the script to create a new wallet.

- `-t` or `--testnet`: This flag specifies that the wallet should be created for the Bitcoin testnet instead of the mainnet. The testnet is used for testing purposes as the coins have no real value. Default is `False`.

- `-w "mywallet"` or `--wallet_name "mywallet"`: This option allows you to specify a custom name for the wallet. If not provided, the script will use the legacy address as the wallet name.

- `-c 5` or `--create 5`: This argument tells the script to create 5 additional addresses in the wallet. If omitted, no extra addresses are created.

- `-p` or `--password`: This flag indicates that the wallet should be encrypted with a password. If a password is not provided immediately after the flag, the script will prompt the user to enter a password securely during execution.

- `-m 256` or `--mnemonic_size 256`: This option allows you to specify the size of the mnemonic (seed phrase) in bits. The script supports sizes of 128, 160, 192, 224, or 256 bits, with 256 being the most secure. If not specified, the default size is 256 bits.

- `-l english` or `--language english`: This argument sets the language for the mnemonic phrase. If not provided, the default language is English.

- `-o` or `--overwrite`: This flag tells the script to overwrite the wallet file if it already exists. Without this flag, the script will prompt the user before overwriting any files.

- `-q` or `--generate_qr`: This flag requests the generation of QR codes for the wallet addresses. If omitted, no QR codes are generated.


## Import Wallet

### Minimal Example:

`python btc_wallet_maker.py import`

This example operates with default settings, targeting the mainnet and only prompting for critical information such as the mnemonic phrase and encryption password. It assumes the mnemonic is in English, does not overwrite existing files without user permission, and generates QR codes solely at the user's request during the process.

### Using all arguments:

`python btc_wallet_maker.py import --mnemonic "your mnemonic phrase here" --testnet --create 5 --wallet_name "importedwallet" --password --language english --overwrite --generate_qr`

or

`python btc_wallet_maker.py import -m "your mnemonic phrase here" -t -c 5 -w "importedwallet" -p -l english -o -q`

### Explanation of each `import` argument:

- `import`: This is the action that tells the script to import an existing wallet using a mnemonic phrase.

- `-m "your mnemonic phrase here"` or `--mnemonic "your mnemonic phrase here"`: This option allows you to provide the mnemonic phrase directly in the command line. If this argument is not provided or is left empty, the script will prompt the user to enter the mnemonic securely during execution.

- `-t` or `--testnet`: This flag specifies that the wallet should be imported for the Bitcoin testnet instead of the mainnet. The testnet is used for testing purposes as the coins have no real value. Default is `False`.

- `-c 5` or `--create 5`: This argument tells the script to create 5 additional addresses in the wallet. If omitted, no extra addresses are created.

- `-w "importedwallet"` or `--wallet_name "importedwallet"`: This option allows you to specify a custom name for the wallet. If not provided, the script will use the legacy address as the wallet name.

- `-p` or `--password`: This flag indicates that the wallet should be encrypted with a password. If a password is not provided immediately after the flag, the script will prompt the user to enter a password securely during execution.

- `-l english` or `--language english`: This argument sets the language for the mnemonic phrase. The script supports multiple languages, and if not provided, the default language is English.

- `-o` or `--overwrite`: This flag tells the script to overwrite the wallet file if it already exists. Without this flag, the script will prompt the user before overwriting any files.

- `-q` or `--generate_qr`: This flag requests the generation of QR codes for the wallet addresses. If omitted, no QR codes are generated.

## View Wallet

### Minimal Example:

`python btc_wallet_maker.py view`

When you run this minimal command, the script will prompt you interactively for the wallet file name and the password since they are not provided as command-line arguments. This is a user-friendly approach for those who prefer not to enter sensitive information, such as a password, directly into the command line.


### Using all arguments:

`python btc_wallet_maker.py view --wallet your_wallet_filename.wallet --password your_password --key legacy_address`

or

`python btc_wallet_maker.py view -w your_wallet_filename.wallet -p your_password -k legacy_address`

### Explanation of each `view` argument:

- `view`: This is the action argument that tells the script to perform the "view" operation, which is to display the wallet details.

- `--wallet` or `-w`: This argument specifies the wallet file name that you want to view. Replace `your_wallet_filename.wallet` with the actual file name of your wallet.

- `--password` or `-p`: This argument is for the password used to encrypt the wallet file. You need to provide this to decrypt and view the wallet details. Replace `your_password` with the actual password.

- `--key` or `-k`: This optional argument allows you to specify a single key whose value you want to display from the wallet. For example, `legacy_address` would display only the legacy address from the wallet. If this argument is omitted, the script will display all wallet details. Valid options are :  `"mnemonic", "testnet", "public_key_hex", "private_key_hex", "private_key_wif",
    "bip38_encrypted_key", "legacy_address", "segwit_address", "nested_segwit_address",
    "taproot_address", "legacy_derivation_path", "legacy_xpub", "legacy_xprv",
    "segwit_derivation_path", "segwit_xpub", "segwit_xprv", "nested_segwit_derivation_path",
    "nested_segwit_xpub", "nested_segwit_xprv", "taproot_derivation_path",
    "taproot_xpub", "taproot_xprv", "addresses_legacy", "addresses_segwit", "addresses_nested_segwit", "addresses_taproot"`

## Features

- **Local Execution**: The script runs on your local machine, eliminating the risks associated with online wallet generators.
- **Mnemonic Phrase Generation**: Securely generate a new mnemonic phrase for wallet creation.
- **Wallet Import**: Import an existing wallet using a mnemonic phrase.
- **Multiple Address Types**: Support for legacy, SegWit, nested SegWit, and Taproot addresses.
- **Encryption**: Wallet details are encrypted using a password provided by the user.
- **QR Code Generation**: Create QR codes for each type of address for easy sharing and transactions.
- **Custom Wallet Names**: Specify custom names for wallet files.
- **Additional Addresses**: Generate additional addresses for your wallet.
- **Language Support**: Mnemonic phrases can be generated in different languages.

## Security

The script uses industry-standard cryptographic algorithms and practices to ensure the security of your wallet:

- **Mnemonic Phrases**: Generated using the `Mnemonic` class from a cryptographically secure pseudorandom number generator.
- **BIP38 Encryption**: Private keys are encrypted using the BIP38 standard, which includes scrypt and AES-256 encryption.
- **Secure Password Handling**: Passwords for encryption are never stored and are prompted for input during runtime.
- **PBKDF2HMAC**: Derives a secure encryption key from the user's password using 300,000 iterations of SHA-512.
- **AES-256 Encryption**: Wallet details are encrypted using AES-256 in CBC mode with a unique initialization vector for each encryption.
- **Scrypt Key Derivation**: Used in BIP38 encryption to provide a high level of resistance against brute-force attacks.

## Wallet Details

The exported wallet includes the following details:

- **Mnemonic**: The mnemonic phrase used to generate the wallet's seed.
- **Testnet**: Indicates whether the wallet is for the Bitcoin testnet.
- **Public Key Hex**: The hexadecimal representation of the wallet's public key.
- **Private Key Hex**: The hexadecimal representation of the wallet's private key.
- **Private Key WIF**: The Wallet Import Format (WIF) of the private key.
- **BIP38 Encrypted Key**: The BIP38 standard encrypted private key.
- **Legacy Address**: The P2PKH address for the wallet.
- **SegWit Address**: The P2WPKH address for the wallet.
- **Nested SegWit Address**: The P2SH-P2WPKH address for the wallet.
- **Taproot Address**: The P2TR address for the wallet.
- **Derivation Paths**: The BIP44, BIP49, and BIP86 derivation paths for the wallet.
- **Extended Public and Private Keys (xpub/xprv)**: For legacy, SegWit, nested SegWit, and Taproot addresses.
- **Addresses**: A list of additional addresses generated for the wallet, if requested.

## User Guidance

While this tool is adept at creating and providing access to your Bitcoin wallet details, it is important to understand its scope. The tool does not facilitate the management or transfer of funds. Users should employ other specialized software or services for transactional purposes. This tool is the first step in securing and accessing your Bitcoin wallet information, setting a strong foundation for your subsequent cryptocurrency activities.

## Conclusion

BTC Wallet Maker stands out for its comprehensive provision of wallet details, simplicity of use, and uncompromising security measures. By delivering a wide array of essential information such as multiple address formats, encrypted private keys, and extended key data, it caters to both novice and experienced users. The tool's straightforward options, combined with the robust AES-256 encryption, ensures that your wallet's integrity and privacy are preserved. Whether you're setting up a new wallet or accessing an existing one, this tool provides a secure and user-friendly pathway to your Bitcoin wallet management.

## Contributing

Contributions are welcome! Please feel free to submit pull requests, report bugs, and suggest features.

## Support

If you need help or have any questions, please open an [issue](https://github.com/x011/BTC-Wallet-Maker/issues).

## License

BTC Wallet Maker is licensed under the GNU General Public License v3.0 (GPL-3.0). For more information, please see the [LICENSE](LICENSE) file.
