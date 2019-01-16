from diameter.AVP import AVP
from diameter.Error import InvalidAVPLengthError
from xdrlib import Packer,Unpacker

def _pack(avps):
    p = Packer()
    for a in avps:
        a.encode(p)
    return p.get_buffer()

class AVP_Grouped(AVP):
    """AVP grouping multiple AVPs together."""

    def __init__(self,code,avps=[],vendor_id=0):
        AVP.__init__(self,code,_pack(avps),vendor_id)

    def getAVPs(self):
        """Returns a copy of the embedded AVPs in a list"""
        avps=[]
        u = Unpacker(self.payload)
        bytes_left=len(self.payload)
        while bytes_left!=0:
            sz = AVP.decodeSize(u,bytes_left)
            if sz==0:
                raise InvalidAVPLengthError(self)
            a = AVP(1,"")
            a.decode(u,sz)
            avps.append(a)
            bytes_left -= sz
        return avps

    def setAVPs(self,avps):
        """Sets the payload to a copy of the AVPs in the list"""
        self.payload = _pack(avps)

    def __str__(self):
        #The default str(...sequence...) looks suboptimal here
        s = ""
        for a in self.getAVPs():
            if s!="": s+=','
            s += a.str_prefix__()
        return str(self.code) + ":[" + s + "]"

    def narrow(avp):
        """Convert generic AVP to AVP_Float64
        Raises: InvalidAVPLengthError
        """
        avps=[]
        u = Unpacker(avp.payload)
        bytes_left=len(avp.payload)
        while bytes_left!=0:
            sz = AVP.decodeSize(u,bytes_left)
            if sz==0:
                raise InvalidAVPLengthError(avp)
            a = AVP(1,"")
            a.decode(u,sz)
            avps.append(a)
            bytes_left -= sz
        a = AVP_Grouped(avp.code, avps, avp.vendor_id)
        a.flags = avp.flags
        return a
    narrow = staticmethod(narrow)

def _unittest():
    a = AVP_Grouped(1)
    assert a.code==1
    assert len(a.getAVPs())==0

    a1 = AVP_Grouped(1,[AVP(2,"u1"),AVP(2,"u2")])
    assert len(a1.getAVPs())==2

    a = AVP(1,"\000\000\000\002\000\000\000\012\165\061\000\000\000\000\000\002\000\000\000\012\165\062\000\000")
    a1 = AVP_Grouped.narrow(a)
    assert len(a1.getAVPs())==2

    a = AVP(1,"\000\000\000\002\000\000\000\012\165\061\000\000\000")
    try:
        a1 = AVP_Grouped.narrow(a)
        assert False
    except InvalidAVPLengthError as details:
        pass

