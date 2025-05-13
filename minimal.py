from migen import *
from migen.sim import run_simulation

from litex.soc.integration.soc_core import SoCCore
from litex.soc.interconnect import wishbone
from litex.soc.interconnect.wishbone import Arbiter
from litex_boards.platforms import digilent_basys3

from SimpleWishboneRam import SimpleWishboneRAM
from AESFromRam import AESFromRAM

class Monitor(Module):
    def __init__(self,bus):
        addr_shifted = Signal(32)
        self.comb += addr_shifted.eq(bus.adr << 2)
        self.comb += Display("tack stb %i, cyc %i, addr %x", bus.stb, bus.cyc, addr_shifted)

class DoNothing(Module):
    def __init__(self,bus):
        pass

class SoC(SoCCore):
    def __init__(self, platform):
        SoCCore.__init__(self, platform, clk_freq=100e6,
                         integrated_rom_size=0x8000, integrated_main_ram_size=0x2000,cpu_type=None)
        # Wishbone SRAM
        self.submodules.ram = wishbone.SRAM(0x1000,init=[0 for _ in range(0x1000>>2)])
        self.add_memory_region("ram", 0x20000000, 0x1000)
        self.bus.add_slave("ram", self.ram.bus)

        aes_master = wishbone.Interface()
        spy_master = wishbone.Interface()

        self.submodules.aes = DoNothing(aes_master)
        self.submodules.spy = DoNothing(spy_master)

        self.submodules.arbiter = Arbiter([aes_master,spy_master],self.ram.bus)

        # Attach Monitor
        self.submodules.monitor = Monitor(self.ram.bus)

def tb(dut):
    print("Learning phase...")
    yield dut.ram.bus.adr.eq((0x20000000) >> 2)
    yield dut.ram.bus.we .eq(0)
    yield dut.ram.bus.cyc.eq(1)
    yield dut.ram.bus.stb.eq(1)
    yield
    print(1)
    yield dut.ram.bus.cyc.eq(0)
    yield dut.ram.bus.stb.eq(0)
    yield
    print(2)
    yield
    print(3)
    yield dut.ram.bus.adr.eq((0x20000004) >> 2)
    yield dut.ram.bus.we.eq(0)
    yield dut.ram.bus.cyc.eq(1)
    yield dut.ram.bus.stb.eq(1)
    yield
    print(4)
    yield
    print(4,"bis")
    yield dut.ram.bus.cyc.eq(0)
    yield dut.ram.bus.stb.eq(0)
    yield
    print(5)
    yield
    print(6)
    return

def main():
    platform = digilent_basys3.Platform()
    soc = SoC(platform)

    run_simulation(soc, tb(soc))

if __name__ == "__main__":
    main()