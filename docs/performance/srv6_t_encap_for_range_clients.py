from trex_stl_lib.api import *
class STLS1(object):

    def __init__ (self):
        self.num_clients  =30000; # max is 16bit

    def create_stream (self, packet_len):
        base_pkt = \
            Ether()/\
            IP(src="10.1.0.1", dst="10.2.0.1")/\
            UDP(dport=10053,sport=10053)

        pad = max(0, packet_len - len(base_pkt)) * 'x'

        vm = STLScVmRaw([
                    STLVmFlowVar(
                        name="ip_src",
                        min_value="10.1.0.1",
                        max_value="10.1.0.255",
                        size=4,
                        step=1,
                        op="inc"
                    ),
                    STLVmWrFlowVar(
                        fv_name="ip_src",
                        pkt_offset= "IP.src",
                    ), # write ip to packet IP.src
                    STLVmFixIpv4(offset = "IP") # fix checksum
            ],
            cache_size = 255 # cache the packets, much better performance
        )

        return STLStream(packet = STLPktBuilder(pkt = base_pkt/pad,vm = vm),
                         mode = STLTXCont())

    def get_streams (self, direction = 0, packet_len = 64, **kwargs):
        # create 1 stream
        return [ self.create_stream(packet_len - 4)]


# dynamic load - used for trex console or simulator
def register():
    return STLS1()
