import os
import sys
import pytest
sys.path.append(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from torcontactinfo import TorContactInfoParser

def test_torcontact_info_multiple_same_named_fields():
    parser = TorContactInfoParser()

    value = "ciissversion:2 url:example.com url:example2.com"
    result = parser.parse(value)
    assert result["url"] == "example.com"


def test_email_address_validation():
    parser = TorContactInfoParser()

    # Valud email
    value = "ciissversion:2 email:test[]example.com"
    result = parser.parse(value)
    assert result["email"] == "test@example.com"

    # Invalid email
    value = "ciissversion:2 email:111"
    result = parser.parse(value)
    assert result["email"] is None

    # Invalid email
    value = "ciissversion:2 email:someone[]somewhere.co.uk"
    result = parser.parse(value)
    assert result["email"] == "someone@somewhere.co.uk"
