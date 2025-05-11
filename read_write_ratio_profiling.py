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

from time import time
import os

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# module to monitor read/write behavior
class ReadWriteMonitor(Module):
    def __init__(self, masters, threshold=10):
        self.masters = masters
        self.read_counts = [Signal(32, reset=0) for _ in masters]
        self.write_counts = [Signal(32, reset=0) for _ in masters]
        self.alerts = [Signal() for _ in masters]
        self.threshold = threshold

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

            # raise alert if the number of 
            self.sync += [
                If(self.read_counts[i] - self.write_counts[i] > self.threshold,
                    self.alerts[i].eq(1)
                ).Else(
                    self.alerts[i].eq(0)
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
        self.bus.add_master("uart", self.uart_master, region=SoCRegion(origin=0x30000000, size=0x1000))

# sim tb
def tb(dut):
    start_time = time()

    print("Waiting for AES to write key...")
    while not (yield dut.aes.ready):
        if (yield dut.aes.debug_write_enable):
            val = (yield dut.aes.debug_write_data)
            addr = (yield dut.aes.addr)
            print(f"AES wrote 0x{val:08x} to 0x{addr:08x}")
        yield

    # Simulate reading the AES key written in RAM
    for _ in range(5):
        yield

    uart_master_status = yield dut.uart_spy.uart_master_status
    last_uart_master_status = uart_master_status  # Store the initial state
    uart_slave_status = yield dut.uart_spy.uart_slave_status

    # Monitor UART master/slave transitions
    uart_master_status = yield dut.uart_spy.uart_master_status
    last_uart_master_status = uart_master_status

    while True:
        if time() - start_time > 500:
            print("Simulation finished.")
            break
        uart_master_status = yield dut.uart_spy.uart_master_status
        uart_slave_status = yield dut.uart_spy.uart_slave_status

        if uart_master_status != last_uart_master_status:
            if uart_master_status:
                print(f"{RED}UART has become MASTER!")
            else:
                print(f"{GREEN}UART has become SLAVE!")
            last_uart_master_status = uart_master_status

        # Only when UART is master, scan the RAM
        if uart_master_status:
            if (yield dut.uart_spy.ready):
                if (yield dut.uart_spy.debug_read_enable):
                    addr = (yield dut.uart_spy.addr)
                    data = (yield dut.uart_spy.debug_read_data)
                    if data != 0:
                        print(f"{YELLOW}UART read 0x{data:08x} from 0x{addr:08x}")

        # Check alerts from the read/write monitor
        for i, alert in enumerate(dut.rw_monitor.alerts):
            if (yield alert):
                print(f"{RED}⚠️  ALERT: Suspicious activity detected from master {i}! Possible trojan active!")

        yield

def main():
    platform = digilent_basys3.Platform()
    soc = DualMasterSoC(platform, simulate=True)
    run_simulation(soc, tb(soc), vcd_name="build/read_write_monitor.vcd")

if __name__ == "__main__":
    main()