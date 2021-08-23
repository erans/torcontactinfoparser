import os
import sys
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from torcontactinfo import TorContactInfoParser

def test_torcontact_info_multiple_same_named_fields():
    parser = TorContactInfoParser()


    value = "ciissversion:2 url:example.com url:example2.com"
    result = parser.parse(value)
    assert result["url"] == "example.com"