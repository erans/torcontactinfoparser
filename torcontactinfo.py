#!/usr/bin/env python3
"""
Tor Contact Info Parser - A tool/Python Class for parsing Tor ContactInfo Information Sharing v2 specification contacts
Written by Eran Sandler  (https://twitter.com/erans) (C) 2018
 With code contributions by @Someguy123 from Privex Inc.

This is a parser for the Tor ContactInfo Information Sharing Specification v2 (https://nusenu.github.io/ContactInfo-Information-Sharing-Specification/).

The parser can parse the ContactInfo field of Tor relays based on the specification.

Official Repo: https://github.com/erans/torcontactinfoparser

Released under the MIT License.
"""
import argparse
import re
import sys
import json
import textwrap
try:
    from rich import print as rprint
    HAS_RICH = True
except ImportError:
    def rprint(value='', *args, **kwargs):
        if value not in [None, False, True] and isinstance(value, (dict, list, set, tuple)):
            value = json.dumps(value, indent=4)
        return print(value, *args, **kwargs)
    # rprint = print
    HAS_RICH = False

from argparse import ArgumentParser

class TorContactInfoParser(object):
    def _parse_string_value(self, value, min_length, max_length, valid_chars, raise_exception=False, field_name=None):
        value_length = len(value)
        if value_length < min_length:
            if raise_exception:
                raise ValueError("value of field '{0}' is too short".format(field_name))
            return None

        if value_length > max_length:
            if raise_exception:
                raise ValueError("value of field '{0}' is too long".format(field_name))
            return None

        if valid_chars != "*":
            m = re.search(valid_chars, value)
            if not m:
                if raise_exception:
                    raise ValueError("value of field '{0}' doesn't match valid chars restrictions".format(field_name))
                else:
                    return None

        return value

    def _parse_email_value(self, value):
        if value:
            return value.replace("[]", "@")

        return value

    _supported_fields_parsers = {
        "email" : _parse_email_value,
        "url" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 4,
                "max_length" : 399,
                "valid_chars" : "[_%/:a-zA-Z0-9.-]+"
            }
        },
        "proof" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 7,
                "max_length" : 7,
                "valid_chars" : "[adinrsu-]+"
            }
        },
        "ciissversion" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 1,
                "max_length" : 1,
                "valid_chars" : "[12]+"
            }
        },
        "pgp" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 40,
                "max_length" : 40,
                "valid_chars" : "[a-zA-Z0-9]+"
            }
        },
        "abuse" : _parse_email_value,
        "keybase" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 0,
                "max_length" : 50,
                "valid_chars" : "[a-zA-Z0-9]+"
            }
        },
        "twitter" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 1,
                "max_length" : 15,
                "valid_chars" : "[a-zA-Z0-9_]+"
            }
        },
        "mastodon" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 0,
                "max_length" : 254,
                "valid_chars" : "*"
            }
        },
        "matrix" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 0,
                "max_length" : 254,
                "valid_chars" : "*"
            }
        },
        "xmpp" : _parse_email_value,
        "otr3" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 40,
                "max_length" : 40,
                "valid_chars" : "[a-z0-9]+"
            }
        },
        "hoster" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 0,
                "max_length" : 254,
                "valid_chars" : "[a-zA-Z0-9.-]+"
            }
        },
        "cost" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 0,
                "max_length" : 13,
                "valid_chars" : "[A-Z0-9.]+"
            }
        },
        "uplinkbw" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 0,
                "max_length" : 7,
                "valid_chars" : "[0-9]+"
            }
        },
        "trafficacct" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 0,
                "max_length" : 7,
                "valid_chars" : "[unmetered0-9]+"
            }
        },
        "memory" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 0,
                "max_length" : 10,
                "valid_chars" : "[0-9]+"
            }
        },
        "cpu" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 0,
                "max_length" : 50,
                "valid_chars" : "[a-zA-Z0-9_-]+"
            }
        },
        "virtualization" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 0,
                "max_length" : 15,
                "valid_chars" : "[a-z-]+"
            }
        },
        "donationurl" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 0,
                "max_length" : 254,
                "valid_chars" : "*"
            }
        },
        "btc" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 26,
                "max_length" : 99,
                "valid_chars" : "[a-zA-Z0-9]+"
            }
        },
        "zec" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 0,
                "max_length" : 95,
                "valid_chars" : "[a-zA-Z0-9]+"
            }
        },
        "xmr" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 0,
                "max_length" : 99,
                "valid_chars" : "[a-zA-Z0-9]+"
            }
        },
        "offlinemasterkey" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 1,
                "max_length" : 1,
                "valid_chars" : "[yn]"
            }
        },
        "signingkeylifetime" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 0,
                "max_length" : 6,
                "valid_chars" : "[0-9]+"
            }
        },
        "sandbox" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 1,
                "max_length" : 2,
                "valid_chars" : "[yn]"
            }
        },
        "os" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 0,
                "max_length" : 20,
                "valid_chars" : "[A-Za-z0-9/.]+"
            }
        },
        "tls" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 0,
                "max_length" : 14,
                "valid_chars" : "[a-z]+"
            }
        },
        "aesni" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 1,
                "max_length" : 1,
                "valid_chars" : "[yn]"
            }
        },
        "autoupdate" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 1,
                "max_length" : 1,
                "valid_chars" : "[yn]"
            }
        },
        "confmgmt" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 1,
                "max_length" : 15,
                "valid_chars" : "[a-zA-Z-]"
            }
        },
        "dnslocation" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 5,
                "max_length" : 100,
                "valid_chars" : "[a-z,]"
            }
        },
        "dnsqname" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 1,
                "max_length" : 1,
                "valid_chars" : "[yn]"
            }
        },
        "dnssec" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 1,
                "max_length" : 1,
                "valid_chars" : "[yn]"
            }
        },
        "dnslocalrootzone" : {
            "fn" : _parse_string_value,
            "args" : {
                "min_length" : 1,
                "max_length" : 1,
                "valid_chars" : "[yn]"
            }
        }
    }

    def __init__(self):
        pass

    def parse(self, value: str, raise_exception_on_invalid_value=False) -> dict:

        # the ciissversion field is mandatory
        if not 'ciissversion:' in value:
            return None

        result = {}
        parts = value.split(" ")
        for p in parts:
            field_parts = p.split(":", 1)
            if len(field_parts) <= 1:
                continue
            name, data = field_parts
            if name in self._supported_fields_parsers:
                field_parser = self._supported_fields_parsers[name]
                if field_parser is None:
                    result[name] = data
                    continue
                if callable(field_parser):
                    value = field_parser(self, data)
                else:
                    field_parser["args"]["field_name"] = name
                    field_parser["args"]["value"] = data
                    field_parser["args"]["raise_exception"] = raise_exception_on_invalid_value

                    value = field_parser["fn"](self, **field_parser["args"])
                result[name] = value

        return result

def cmd_parse(opts: argparse.Namespace):
    """
    ArgParser function for parsing a single ContactInfo string, and outputting it as JSON (or python-style dict's)
    """

    if opts.contact is None or len(opts.contact) == 0 or opts.contact[0] == '-':
        contact = sys.stdin.read()
    else:
        contact = ' '.join(opts.contact).strip()

    tparser = TorContactInfoParser()
    res = tparser.parse(contact)
    if not opts.pretty:
        return print(json.dumps(res))
    if opts.json: res = json.dumps(res, indent=4) if opts.pretty else json.dumps(res)
    # if not HAS_RICH: res = json.dumps(res, indent=4)
    rprint(res)

    

def cmd_scan(opts: argparse.Namespace):
    """
    ArgParser function for scanning all ContactInfo strings from ``https://onionoo.torproject.org/details`` ,
    and outputting each one as a Python-style Dict, or JSON.
    """
    import requests

    parser = TorContactInfoParser()

    data = requests.get("https://onionoo.torproject.org/details").json()
    for r in data["relays"]:
        contact = r.get("contact", None)
        if not contact: continue
        result = parser.parse(contact, False)
        if len(result) > 0:
            if opts.json: result = json.dumps(result, indent=4) if opts.pretty else json.dumps(result)
            if opts.pretty:
                rprint(result)
            else:
                print(result)


def main():
    cparser = ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(f"""
    Examples:

        # 'scan' is the original behaviour of this script. It iterates over the data 
        # from https://onionoo.torproject.org/details , parses each contact, and prints it as Python dict-style JSON.
        {sys.argv[0]} scan
        
        # Same as previous. With no arguments, it's equivalent to running 'scan'.
        {sys.argv[0]}
        
        # If you pass '-p' after scan, it will enable pretty printing. For best pretty printing,
        # make sure you have 'rich' installed from pypi.
        {sys.argv[0]} scan -p

        # If you need real JSON with double quotes, rather than Python dict-style JSON, you can
        # use the '-j' flag to enable "real JSON" mode (you can combine with '-p' if you want pretty printed real json)
        {sys.argv[0]} scan -j

        # Using 'parse', you can parse an arbitrary ContactInfo string, and it will output the parsed result
        # with pretty printing by default.

        {sys.argv[0]} parse "contact Mr.Example email:me[]example.com url:https://www.example.com " \\
                "proof:uri-rsa pgp:288DD1632F6E8951 keybase:examplecom twitter:Example hoster:www.example.com " \\
                "uplinkbw:500 memory:4096 virtualization:kvm btc:bc1qpst9uscvd8rpjjhzz9rau3trylh6e0wh76qrlhw3q9nj89ua728sn3t6a2 " \\
                "xmr:89tukP3wfpH4FZAmC1D2GfArWwfPTz8Ap46NZc54Vyhy9YxEUYoFQ7HGQ74LrCMQTD3zxvwM1ewmGjH9WVmeffwR72m1Pps"
        
            {{
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
            }}
        
        # You can also pipe a contact string into 'parse', and it will work just the same.

        echo "Mr. Example email:me[]example.com url:https://www.example.com proof:uri-rsa pgp:288DD1632F6E8951 keybase:examplecom twitter:Example" | {sys.argv[0]} parse
        {{'email': 'me@example.com', 'url': 'https://www.example.com', 'proof': 'uri-rsa', 'pgp': None, 'keybase': 'examplecom', 'twitter': 'Example\n'}}

        # If you need real JSON outputted, rather than Python dict-style output, you can pass -j to either 'parse' or 'scan'

        {sys.argv[0]} parse -j "Mr. Example email:me[]example.com url:https://www.example.com proof:uri-rsa pgp:288DD1632F6E8951 keybase:examplecom twitter:Example"
            {{
                "email": "me@example.com",
                "url": "https://www.example.com",
                "proof": "uri-rsa",
                "pgp": null,
                "keybase": "examplecom",
                "twitter": "Example"
            }}

        # You can use '-np' to disable pretty printing for 'parse' - you can combine it with '-j' to get flat, plain JSON.

        {sys.argv[0]} parse -np -j "Mr. Example email:me[]example.com url:https://www.example.com proof:uri-rsa pgp:288DD1632F6E8951 keybase:examplecom twitter:ExampleCom"
            {{"email": "me@example.com", "url": "https://www.example.com", "proof": "uri-rsa", "pgp": null, "keybase": "examplecom", "twitter": "Example"}}
    """))
    cparser.set_defaults(func=cmd_scan, json=False, pretty=False)
    subparse = cparser.add_subparsers()
    subparse.required = False
    sp_parse = subparse.add_parser('parse', help="Parse a single contact string, either as an argument, or piped into stdin")
    sp_parse.add_argument('contact', nargs='*')
    sp_parse.add_argument('-np', '--no-pretty', action='store_false', default=True, dest='pretty', help="Disable pretty printing JSON")
    sp_parse.add_argument('-j', '--json', action='store_true', default=False, dest='json', help="Output real JSON, not Python dict format.")
    sp_parse.set_defaults(func=cmd_parse)

    sp_scan = subparse.add_parser('scan', help="Parse all contacts from https://onionoo.torproject.org/details")
    sp_scan.add_argument('-p', action='store_true', default=False, dest='pretty', help="Enable pretty printing JSON")
    sp_scan.add_argument('-j', '--json', action='store_true', default=False, dest='json', help="Output real JSON, not Python dict format.")

    sp_scan.set_defaults(func=cmd_scan)

    args = cparser.parse_args()

    args.func(args)



if __name__ == "__main__":
    main()

