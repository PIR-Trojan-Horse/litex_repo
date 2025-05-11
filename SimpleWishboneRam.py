from migen import Signal,Memory,If,Module
from litex.soc.interconnect import wishbone

# ----------- Personal RAM component -----------
class SimpleWishboneRAM(Module):
    def __init__(self, size=0x1000, init=None):
        self.bus = wishbone.Interface()

        mem_depth = size // 4  # nombre de mots 32 bits
        mem = Memory(32, mem_depth, init=init)  # 32 bits par mot

        # Create a Wishbone port (one port, read-write)
        port = mem.get_port(write_capable=True)
        self.specials += mem, port

        # Connect Wishbone to memory port
        self.comb += [
            port.adr.eq(self.bus.adr),
            port.dat_w.eq(self.bus.dat_w),
            self.bus.dat_r.eq(port.dat_r),
            port.we.eq(self.bus.we & self.bus.stb & self.bus.cyc),
            self.bus.ack.eq(self.bus.stb & self.bus.cyc)
        ]
        self.sync += [
            If(self.bus.stb & self.bus.cyc & self.bus.we, 
                # Printing the values in the simulation
                #print("Write to address 0x{:08x} with data 0x{:08x}".format((yield self.bus.adr), (yield self.bus.dat_w)))
            )
        ]