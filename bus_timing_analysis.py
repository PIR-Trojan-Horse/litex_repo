from migen import *
from migen.genlib.fsm import FSM, NextState
from migen.sim import run_simulation
from migen.genlib.resetsync import AsyncResetSynchronizer

from litex.soc.integration.soc_core import SoCCore, SoCRegion
from litex.soc.interconnect.csr import AutoCSR, CSRStatus
from litex.soc.interconnect import wishbone
from litex.soc.interconnect.wishbone import Arbiter, SRAM
from litex_boards.platforms import digilent_basys3
from migen import *
from migen.genlib.fsm import FSM, NextState, NextValue
from time import time

import os

from AESFromRam import AESFromRAM
from SimpleWishboneRam import SimpleWishboneRAM

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# ----------- Generic Bus Monitor (detects suspicious activity) -----------
class TimingAnalysis(Module):
    def __init__(self, arbiter_bus, minimum_legitimate_access, maximum_legitimate_access):
        # self.profiling = Signal(reset=1)
        self.alert = Signal()
        self.reading = Signal()
        self.read_counter = Signal(max=maximum_legitimate_access+1,reset=(maximum_legitimate_access+minimum_legitimate_access)//2)
        assert minimum_legitimate_access < maximum_legitimate_access
        self.minimum_acess = minimum_legitimate_access
        self.maximum_acess = maximum_legitimate_access
        
        self.comb += self.alert.eq(((self.read_counter > maximum_legitimate_access) & self.reading) | ((self.read_counter < minimum_legitimate_access) & ~self.reading))

        self.sync += [
            # Display("%i %i => %i",self.reading,self.read_counter,self.alert),
            If(self.reading,
                If(arbiter_bus.stb & arbiter_bus.cyc,
                   If(self.read_counter <= maximum_legitimate_access,self.read_counter.eq(self.read_counter + 1))
                ).Else(
                    self.reading.eq(0)
                )
            ).Else(
                If(arbiter_bus.stb & arbiter_bus.cyc,
                    self.read_counter.eq(1),
                    self.reading.eq(1)
                )
            ),
        ]

# ----------- UART Spy (lit depuis RAM) -----------
class UARTSpy(Module):
    def __init__(self, bus):
        self.bus = bus  # Wishbone master interface
        self.ready = Signal(reset=0)
        self.addr = Signal(32)
        self.index = Signal(10)  # 10 bits to count up to 1024 words
        self.data = Signal(32)
        self.debug_read_data = Signal(32)
        self.debug_read_enable = Signal()
        self.uart_master_status = Signal()  # Status signal for UART becoming master
        self.uart_slave_status = Signal()   # Status signal for UART becoming slave

        self.submodules.fsm = FSM(reset_state="IDLE")

        # Variables de temporisation
        self.time_counter = Signal(32)

        # Machine à états
        self.fsm.act("IDLE",
            NextValue(self.time_counter, 0),
            If(self.time_counter == 10,
                NextState("BECOME_MASTER")
            ).Else(
                NextValue(self.time_counter, self.time_counter + 1)
            )
        )

        self.fsm.act("BECOME_MASTER",
            NextValue(self.addr, 0x20000000),
            NextValue(self.index, 0),
            NextValue(self.uart_master_status, 1),
            NextState("READ_KEY")
        )

        self.fsm.act("READ_KEY",
            self.bus.adr.eq(self.addr[2:]),
            self.bus.stb.eq(1),
            self.bus.cyc.eq(1),
            self.bus.we.eq(0),
            self.debug_read_data.eq(self.data),
            self.debug_read_enable.eq(0),
            If(self.bus.ack,
                self.debug_read_enable.eq(1),
                self.data.eq(self.bus.dat_r),
                self.ready.eq(1),
                NextValue(self.addr, self.addr + 4),
                If(self.addr + 4 >= 0x20001000,
                    NextState("WAIT_BEFORE_RESCAN") # we cycle to sleep for a while before rescanning
                ).Else(
                    NextState("READ_KEY")
                )

            )
        )

        self.fsm.act("WAIT_BEFORE_RESCAN",
            NextValue(self.uart_master_status, 0),  # UART is no longer master
            NextValue(self.uart_slave_status, 1),
            NextValue(self.bus.stb, 0),
            NextValue(self.bus.cyc, 0),
            NextValue(self.bus.we, 0),
            NextValue(self.debug_read_enable, 0),
            If(self.time_counter >= (5000),  # about ~10s
                NextValue(self.time_counter, 0),
                NextValue(self.addr, 0x20000000),  # Reset address
                NextState("BECOME_MASTER")  # Restart reading
            ).Else(
                NextValue(self.time_counter, self.time_counter + 1)
            )
        )

        self.fsm.act("DONE",
            self.ready.eq(1),
            self.bus.cyc.eq(0),
            self.bus.stb.eq(0),
            self.bus.we.eq(0),
        )

# ----------- SoC Definition -----------
class DualMasterSoC(SoCCore):
    def __init__(self, platform, simulate=False):
        SoCCore.__init__(self, platform, clk_freq=100e6, cpu_type=None,
                         integrated_rom_size=0x8000,
                         integrated_main_ram_size=0x0000)

        # Shared RAM
        #ram = SRAM(0x1000, init=None) # real ram, not working
        self.submodules.ram = SimpleWishboneRAM(size=0x1000)
        
        # 2 masters: AES and UART
        self.aes_master = wishbone.Interface()
        self.uart_master = wishbone.Interface()

        self.submodules.aes = AESFromRAM(self.aes_master)
        self.submodules.uart_spy = UARTSpy(self.uart_master)
        self.submodules.timing_monitor = TimingAnalysis(self.ram.bus,20,100)

        # Wishbone arbiter
        self.submodules.arbiter = Arbiter([self.aes_master, self.uart_master], self.ram.bus)

        # Memory map
        self.bus.add_slave("shared_ram", self.ram.bus,region=SoCRegion(origin=0x20000000, size=0x1000))
        self.bus.add_master("aes", master=self.aes_master)
        self.bus.add_slave("uart", self.uart_master, region=SoCRegion(origin=0x30000000, size=0x1000))  # Example address region for UART
        
# ----------- Simulation Testbench -----------
def tb(dut):
    start_time = time()
    def wb_read(bus, addr):
        yield bus.adr.eq(addr >> 2)
        yield bus.we.eq(0)
        yield bus.stb.eq(1)
        yield bus.cyc.eq(1)
    
        while True:
            if (yield bus.ack):
                break
            yield
    
        # Yield once more before reading dat_r
        yield
        val = (yield bus.dat_r)
    
        yield bus.stb.eq(0)
        yield bus.cyc.eq(0)
        yield
        return val

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
        if time() - start_time > 25:
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
            # ✨ NEW: Monitor each time `ready` goes high
            if (yield dut.uart_spy.ready):
                if (yield dut.uart_spy.debug_read_enable):
                    addr = (yield dut.uart_spy.addr)
                    data = (yield dut.uart_spy.debug_read_data)
                    if data != 0:
                        print(f"{YELLOW}UART read 0x{data:08x} from 0x{addr:08x}")

        current_alert = yield dut.timing_monitor.alert
        if current_alert and not last_alert:
            current_counter = (yield dut.timing_monitor.read_counter)
            print(f"{RED}⚠️  ALERT: Suspicious activity detected! Possible trojan active! ({current_counter} read)")
        last_alert = current_alert
        yield 
    
# ----------- Run Simulation -----------
def main():
    platform = digilent_basys3.Platform()
    soc = DualMasterSoC(platform, simulate=True)

    if not os.path.exists("build/"):
        os.makedirs("build/")
    run_simulation(soc, tb(soc), vcd_name="build/timing_analysis.vcd")

if __name__ == "__main__":
    main()
