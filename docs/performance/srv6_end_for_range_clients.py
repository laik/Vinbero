from trex_stl_lib.api import *

class STLS1(object):

    def __init__ (self):
        self.num_clients  =30000; # max is 16bit

    def create_stream (self, packet_len):
        addresses=["fc00:3::3", "fc00:2::2"]
        base_pkt = \
            Ether()/\
            IPv6(src="fc00:1::1", dst="fc00:2::2")/\
            IPv6ExtHdrSegmentRouting(len=(16 * len(addresses)) // 8, segleft=len(addresses)-1, lastentry=len(addresses)-1, addresses=addresses)/ \
            IP(src="192.168.1.1", dst="192.168.1.2")/\
            UDP(sport=10053,dport=10053)

        pad = max(0, packet_len - len(base_pkt)) * 'x'

        vm = STLScVmRaw([
                STLVmFlowVar(
                    name="ipv6_src",
                    min_value="16.0.0.0",
                    max_value="18.0.0.254",
                    size=4,
                    op="random",
                ),
                STLVmWrFlowVar(
                    fv_name="ipv6_src",
                    pkt_offset= "IPv6.src",
                    offset_fixup=12,
                ),
            ],
        )

        return STLStream(packet = STLPktBuilder(pkt = base_pkt/pad,vm = vm),
                         mode = STLTXCont())

    def get_streams (self, direction = 0, packet_len = 64, **kwargs):
        # create 1 stream
        return [ self.create_stream(packet_len - 4)]


# dynamic load - used for trex console or simulator
def register():
    return STLS1()
