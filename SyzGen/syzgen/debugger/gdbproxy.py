
import logging

from .proxy import Proxy

logger = logging.getLogger(__name__)

class GDBProxy(Proxy):
    '''GDB Proxy used by angr to retrieve code and data
    '''

    def __init__(self, port=12345):
        super(GDBProxy, self).__init__(port=port)

    def read_memory(self, addr, size):
        request = {
            "cmd": "read mem",
            "addr": addr,
            "size": size
        }
        return self.request(request, fmt="binary") 

