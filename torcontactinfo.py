import re

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
        "cpu" : None,
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

    def parse(self, value, raise_exception_on_invalid_value=False):
        result = {}
        parts = value.split(" ")
        for p in parts:
            field_parts = p.split(":", 1)
            if len(field_parts) > 1:
                if field_parts[0] in self._supported_fields_parsers:
                    field_parser = self._supported_fields_parsers[field_parts[0]]
                    if field_parser is None:
                        result[field_parts[0]] = field_parts[1]
                    else:
                        if callable(field_parser):
                            value = field_parser(self, field_parts[1])
                        else:
                            field_parser["args"]["field_name"] = field_parts[0]
                            field_parser["args"]["value"] = field_parts[1]
                            field_parser["args"]["raise_exception"] = raise_exception_on_invalid_value

                            value = field_parser["fn"](self, **field_parser["args"])
                            result[field_parts[0]] = value

        return result

if __name__ == "__main__":
    import requests

    parser = TorContactInfoParser()

    data = requests.get("https://onionoo.torproject.org/details").json()
    for r in data["relays"]:
        contact = r.get("contact", None)
        if contact:
            result = parser.parse(contact, False)
            if len(result) > 0:
                print(result)
