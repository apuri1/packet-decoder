import re
import thread
from diameter.node.Error import InvalidSettingError

class NodeSettings:
    """Configuration for a Node"""
    
    def __init__(self,host_id, realm, vendor_id, capabilities, port, product_name, firmware_revision):
        if not host_id or host_id=="":
            raise InvalidSettingError("No host_id")
        if len(re.split("\.",host_id))<3:
            raise InvalidSettingError("host_id must contains at least 2 dots")
        self.host_id = host_id
        
        if not realm or realm=="":
            raise InvalidSettingError("null realm")
        if len(re.split("\.",realm))<2:
            raise InvalidSettingError("realm must contains at least 1 dot")
        self.realm = realm
        
        if vendor_id==0:
            raise InvalidSettingError("vendor_id must not be non-zero. (It must be your IANA-assigned \"SMI Network Management Private Enterprise Code\". See http://www.iana.org/assignments/enterprise-numbers)")
        self.vendor_id = vendor_id
        
        if capabilities.isEmpty():
            raise InvalidSettingError("Capabilities must be non-empty")
        self.capabilities = capabilities
        
        if port<0 or port>65535:
            raise InvalidSettingError("listen-port must be 0..65535")
        self.port = port
        
        if not product_name:
            raise InvalidSettingError("product-name cannot be None");
        self.product_name = product_name
        
        self.firmware_revision = firmware_revision

from Capability import Capability

def _unittest():
    cap = Capability(); cap.addAuthApp(117)
    try:
        ns = NodeSettings("example.net","example.net",-1,cap,3868,"PythonDiameter",1)
        assert False
    except InvalidSettingError:
        pass
    try:
        ns = NodeSettings("somehost.example.net","net",-1,cap,3868,"PythonDiameter",1)
        assert False
    except InvalidSettingError:
        pass
    try:
        ns = NodeSettings("somehost.example.net","example.net",0,cap,3868,"PythonDiameter",1)
        assert False
    except InvalidSettingError:
        pass
    try:
        empty_cap = Capability()
        ns = NodeSettings("somehost.example.net","example.net",0,empty_cap,3868,"PythonDiameter",1)
        assert False
    except InvalidSettingError:
        pass
    try:
        ns = NodeSettings("somehost.example.net","example.net",-1,cap,-4,"PythonDiameter",1)
        assert False
    except InvalidSettingError:
        pass
    try:
        ns = NodeSettings("somehost.example.net","example.net",-1,cap,65536,"PythonDiameter",1)
        assert False
    except InvalidSettingError:
        pass
    try:
        ns = NodeSettings("somehost.example.net","example.net",-1,cap,3868,None,1)
        assert False
    except InvalidSettingError:
        pass
        
    try:
        ns = NodeSettings("somehost.example.net","example.net",-1,cap,3868,"PythonDiameter",1)
    except InvalidSettingError:
        assert False
