import time
import thread
import random

class NodeState:
    
    def __init__(self):
        now = long(time.time())
        self.state_id = now
        self.end_to_end_identifier = int((now<<20) | random.randint(0,0x000FFFFF))&0xFFFFFFFF
        self.session_id_high = now
        self.session_id_low = 0
        self.lock = thread.allocate_lock()
    
    def nextEndToEndIdentifier(self):
        self.lock.acquire()
        v = self.end_to_end_identifier
        self.end_to_end_identifier += 1
        self.lock.release()
        return v
    
    def nextSessionId_second_part(self):
        self.lock.acquire()
        v = self.session_id_low
        self.session_id_low += 1
        if self.session_id_low == 0:
            self.session_id_high += 1
        self.lock.release()
        return str(self.session_id_high) + ";" + str(v)
        

def _unittest():
    ns = NodeState()
    i1 = ns.nextEndToEndIdentifier()
    i2 = ns.nextEndToEndIdentifier()
    assert i1!=i2
    
    sp1 = ns.nextSessionId_second_part()
    sp2 = ns.nextSessionId_second_part()
    assert sp1 != sp2
    
