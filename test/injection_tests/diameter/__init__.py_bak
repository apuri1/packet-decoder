# -*- coding: iso-8859-1 -*-
"""Diameter Messages and AVPs.
This package contains classes for low-level dealing with Diameter messages
and AVPs.

The Message class contains a MessageHeader and a bunch of AVPs. The AVP
classes are modelled after RFC3588. See {@link dk.i1.diameter.Message} to
see examples of how to build and process messages.

ProtocolConstants contains symbolic constants from the RFCs.

Utils contains some utilities that a useful, particular for setting the
M-bit on AVPs.


Note: The following AVP types described in RFC358 have not been implemented:
    DiameterIdentity
        Basically a AVP_UTF8String. The RFC says that it is the FQDN of a
        node, but violations of this have been seen in the real world.
    DiameterURI
        A URI with certain rules. Not seen in the real world (yet)
    Enumerated
        Use AVP_Unsigned32 instead
    IPFilterRule
    QoSFilterRule
        Presumable specific to NASREQ</dd>
"""

from AVP import AVP
from AVP_Address import AVP_Address
from AVP_Float32 import AVP_Float32
from AVP_Float64 import AVP_Float64
from AVP_Grouped import AVP_Grouped
from AVP_OctetString import AVP_OctetString
from AVP_Time import AVP_Time
from AVP_UTF8String import AVP_UTF8String
from AVP_Unsigned32 import AVP_Unsigned32
from AVP_Unsigned64 import AVP_Unsigned64
from Error import InvalidAVPLengthError,InvalidAddressTypeError,InvalidAVPValueError
from Message import Message
from MessageHeader import MessageHeader
from ProtocolConstants import *
from Utils import *

__author__="Ivan Skytte Jørgensen"

def _unittest():
    pass
