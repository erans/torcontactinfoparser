# Tor Contact Info Parser - A tool/Python Class for parsing Tor ContactInfo Information Sharing v2 specification contacts

Written by Eran Sandler ([@erans](https://twitter.com/erans)) &copy; 2018 \
With code contributions by [@Someguy123](https://github.com/someguy123) from Privex Inc.

This is a parser for the
[Tor ContactInfo Information Sharing Specification](https://nusenu.github.io/ContactInfo-Information-Sharing-Specification/) (version 2).

The parser can parse the ContactInfo field of Tor relays based on the specification.

Official Repo: <https://github.com/erans/torcontactinfoparser>

## Requirements

- Python 3.6 or newer (Tested on Python 3.9)
- A terminal to run the script with
- Should work on any operating system which can run Python, and can install Python packages - including Linux, macOS, BSDs, and Windows
- Info about optional Python package dependencies:
  - The `parse` sub-command should be usable from any standard Python 3.6+ installation, as it's dependency free. However, for nicer pretty printing,
    you may want to install the `rich` PyPi package using `pip3` (included in the `requirements.txt`).
  - The `scan` sub-command requires the Python HTTP Requests library `requests` - and can also take advantage of `rich` if installed.

## Quickstart

```sh
# Clone the repo
git clone https://github.com/erans/torcontactinfoparser.git
cd torcontactinfoparser
# NOTE: You don't need any external packages to use the 'parse' command, however, you should install the optional dependencies
# from requirements.txt for the best user experience.
pip3 install -U -r requirements.txt

# The easiest way to use the parse command, is simply to pass the contact string as positional arguments. You can specify it as either
# a single string in the first argument:
./torcontactinfo.py parse "Privex Inc. email:noc[]privex.io url:https://www.privex.io proof:uri-rsa pgp:288DD1632F6E8951 keybase:privexinc twitter:PrivexInc"
# Or you can split it across multiple arguments if you need/want to do so:
./torcontactinfo.py parse Privex Inc. "email:noc[]privex.io url:https://www.privex.io" \
    "proof:uri-rsa pgp:288DD1632F6E8951" keybase:privexinc twitter:PrivexInc

# You can also pipe a contact string into the parse command.
echo "Privex Inc. email:noc[]privex.io url:https://www.privex.io" \
     "proof:uri-rsa pgp:288DD1632F6E8951 keybase:privexinc twitter:PrivexInc" | ./torcontactinfo.py parse

# The scan command is primarily used by @nusenu for populating the contact details in some of their public services,
# but you can use it too, if you have a use for it :)
./torcontactinfo.py scan

# For backwards compatibility, the scan command is ran by default if you don't pass any arguments
./torcontactinfo.py

# To enable pretty printing for the scan command, simply add the argument '-p'
./torcontactinfo.py scan -p
```

## Examples

### Using the `parse` subcommand

```sh
# Using 'parse', you can parse an arbitrary ContactInfo string, and it will output the parsed result
# with pretty printing by default.

./torcontactinfo.py parse "contact Privex Inc. email:me[]example.com url:https://www.example.com " \
        "proof:uri-rsa pgp:288DD1632F6E8951 keybase:examplecom twitter:Example hoster:www.example.com " \
        "uplinkbw:500 memory:4096 virtualization:kvm btc:bc1qpst9uscvd8rpjjhzz9rau3trylh6e0wh76qrlhw3q9nj89ua728sn3t6a2 " \
        "xmr:89tukP3wfpH4FZAmC1D2GfArWwfPTz8Ap46NZc54Vyhy9YxEUYoFQ7HGQ74LrCMQTD3zxvwM1ewmGjH9WVmeffwR72m1Pps"

    {
        'email': 'me@example.com',
        'url': 'https://www.example.com',
        'proof': 'uri-rsa',
        'pgp': None,
        'keybase': 'examplecom',
        'twitter': 'Example',
        'hoster': 'www.example.com',
        'uplinkbw': '500',
        'memory': '4096',
        'virtualization': 'kvm',
        'btc': 'bc1qpst9uscvd8rpjjhzz9rau3trylh6e0wh76qrlhw3q9nj89ua728sn3t6a2',
        'xmr': '89tukP3wfpH4FZAmC1D2GfArWwfPTz8Ap46NZc54Vyhy9YxEUYoFQ7HGQ74LrCMQTD3zxvwM1ewmGjH9WVmeffwR72m1Pps'
    }

# You can also pipe a contact string into 'parse', and it will work just the same.

echo "Mr Example email:me[]example.com url:https://www.example.com proof:uri-rsa pgp:288DD1632F6E8951 keybase:examplecom twitter:Example" | ./torcontactinfo.py parse

    {'email': 'me@pexample.com', 'url': 'https://www.example.com', 'proof': 'uri-rsa', 'pgp': None, 'keybase': 'examplecom', 'twitter': 'Example'}

# If you need real JSON outputted, rather than Python dict-style output, you can pass -j to either 'parse' or 'scan'

./torcontactinfo.py parse -j "Mr Example email:me[]example.com url:https://www.example.com proof:uri-rsa pgp:288DD1632F6E8951 keybase:examplecom twitter:Example"

    {
        "email": "me@example.com",
        "url": "https://www.example.com",
        "proof": "uri-rsa",
        "pgp": null,
        "keybase": "examplecom",
        "twitter": "Example"
    }

# You can use '-np' to disable pretty printing for 'parse' - you can combine it with '-j' to get flat, plain JSON.

./torcontactinfo.py parse -np -j "Mr Example email:me[]example.com url:https://www.example.com proof:uri-rsa pgp:288DD1632F6E8951 keybase:examplecom twitter:Example"

    {"email": "me@example.com", "url": "https://www.example.com", "proof": "uri-rsa", "pgp": null, "keybase": "examplecom", "twitter": "Example"}

```

### Using the `scan` subcommand

```sh
# 'scan' is the original behaviour of this script. It iterates over the data 
# from https://onionoo.torproject.org/details , parses each contact, and prints it as Python dict-style JSON.
./torcontactinfo.py scan

# Same as previous. With no arguments, it's equivalent to running 'scan'.
./torcontactinfo.py

# If you pass '-p' after scan, it will enable pretty printing. For best pretty printing,
# make sure you have 'rich' installed from pypi.
./torcontactinfo.py scan -p

# If you need real JSON with double quotes, rather than Python dict-style JSON, you can
# use the '-j' flag to enable "real JSON" mode (you can combine with '-p' if you want pretty printed real json)
./torcontactinfo.py scan -j
```
