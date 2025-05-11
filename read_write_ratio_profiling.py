from migen import *
from migen.genlib.fsm import FSM, NextState
from migen.sim import run_simulation
from litex.soc.integration.soc_core import SoCCore, SoCRegion
from litex.soc.interconnect import wishbone
from litex.soc.interconnect.wishbone import Arbiter, SRAM
from litex_boards.platforms import digilent_basys3

# import other modules
from arbiter_masters import AESFromRAM
from arbiter_masters import SimpleWishboneRAM
from arbiter_masters import UARTSpy

# module to monitor read/write behavior
class ReadWriteMonitor(Module):
    def __init__(self, masters):
        self.masters = masters
        self.read_counts = [Signal(32, reset=0) for _ in masters]
        self.write_counts = [Signal(32, reset=0) for _ in masters]
        self.read_write_ratios = [Signal(32) for _ in masters]

        for i, master in enumerate(masters): # for each masters on the bus
            # keep track of reads and writes
            self.sync += [
                If(master.stb & master.cyc,
                    If(master.we,
                        self.write_counts[i].eq(self.write_counts[i] + 1)
                    ).Else(
                        self.read_counts[i].eq(self.read_counts[i] + 1)
                    )
                )
            ]

            # get their corresponding ratios
            total = Signal(32)
            self.sync += [
                total.eq(self.read_counts[i] + self.write_counts[i]),
                If(total > 0,
                    self.read_write_ratios[i].eq((self.read_counts[i] * 100) // total)
                ).Else(
                    self.read_write_ratios[i].eq(0)
                )
            ]

# SoC with monitor and two masters
class DualMasterSoC(SoCCore):
    def __init__(self, platform, simulate=False):
        SoCCore.__init__(self, platform, clk_freq=100e6, cpu_type=None,
                         integrated_rom_size=0x8000,
                         integrated_main_ram_size=0x0000)

        # shared RAM
        self.submodules.ram = SimpleWishboneRAM(size=0x1000)

        # setup masters (UART and AES)
        self.aes_master = wishbone.Interface()
        self.uart_master = wishbone.Interface()

        self.submodules.aes = AESFromRAM(self.aes_master)
        self.submodules.uart_spy = UARTSpy(self.uart_master)

        # add read/write monitor
        self.submodules.rw_monitor = ReadWriteMonitor([self.aes_master, self.uart_master])

        # add the arbiter
        self.submodules.arbiter = Arbiter([self.aes_master, self.uart_master], self.ram.bus)

        # map memory regions
        self.bus.add_slave("shared_ram", self.ram.bus, region=SoCRegion(origin=0x20000000, size=0x1000))
        self.bus.add_master("aes", master=self.aes_master)
        self.bus.add_slave("uart", self.uart_master, region=SoCRegion(origin=0x30000000, size=0x1000))

# sim tb
def tb(dut):
    yield

def main():
    platform = digilent_basys3.Platform()
    soc = DualMasterSoC(platform, simulate=True)
    run_simulation(soc, tb(soc), vcd_name="build/read_write_monitor.vcd")

if __name__ == "__main__":
    main()