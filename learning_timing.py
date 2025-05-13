from migen import *
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

from learning_marb_buscounters import AESFromRAM
from SimpleWishboneRam import SimpleWishboneRAM

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# ----------- "Generic" Bus Monitor (using thresholds and learning to detect trojans) -----------
class LearningTimingAnalysis(Module):
    def __init__(self, arbiter_bus,name : str):
        self.learning = Signal(reset=1)
        self.minimum = Signal(16,reset=65535)
        self.maximum = Signal(16,reset=0)
        self.alert = Signal()
        self.reading = Signal()
        self.read_counter = Signal(16)
        self.offtime = Signal(8)

        self.comb += self.alert.eq(
            ~self.learning & (
            ((self.read_counter > self.maximum) & self.reading) | 
            ((self.read_counter < self.minimum) & ~self.reading))
        )

        self.sync += [
            # If(~self.learn & self.alert,Display(f"{name} r: %i cnt: %i ([%i,%i]), sca: %i%i%i",self.reading,self.read_counter,self.minimum,self.maximum,arbiter_bus.stb,arbiter_bus.cyc,arbiter_bus.ack)),
            If(self.reading,
                If(arbiter_bus.stb & arbiter_bus.cyc & arbiter_bus.ack, # count ack to not "overcount" slow communication
                   self.read_counter.eq(self.read_counter + 1)
                ).Elif(self.offtime == 2,
                    # Display(f"[{name}] Stopped reading (cnt = %i)",self.read_counter),
                    self.reading.eq(0),
                    self.offtime.eq(0)
                ).Else(
                    self.offtime.eq(self.offtime + 1)
                )
            ).Else(
                If(arbiter_bus.stb & arbiter_bus.cyc,
                    self.read_counter.eq(1),
                    self.reading.eq(1)
                )
            ),
            If(self.learning,
            #    Display("Learning: cnt = %i, thresh = [%i,%i]",self.read_counter,self.minimum,self.maximum),
            #    Display("Bus: %i %i %i",arbiter_bus.stb,arbiter_bus.cyc,arbiter_bus.we),
               If(self.read_counter < self.minimum,self.minimum.eq(self.read_counter)),
               If(self.read_counter > self.maximum,self.maximum.eq(self.read_counter))
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
        cooldown = 10
        max_lawfullness = 25
        self.time_counter = Signal(32)
        self.lawfullness = Signal(8,reset=0)

        # Finite State Machine (Machine à états)
        self.fsm.act("IDLE",
            NextValue(self.time_counter, 0),
            If(self.time_counter == cooldown,
                If(self.lawfullness == max_lawfullness,
                    NextValue(self.lawfullness,0),
                    NextState("BECOME_SPY")
                ).Else(
                    NextValue(self.lawfullness,self.lawfullness + 1),
                    NextState("BECOME_MASTER")
                )
            ).Else(
                NextValue(self.time_counter, self.time_counter + 1)
            )
        )

        self.fsm.act("BECOME_MASTER",
            NextValue(self.addr,0x20001000),
            NextValue(self.uart_master_status,1),
            NextState("UART_ROUTINE_WRITE")
        )

        self.fsm.act("UART_ROUTINE_WRITE",
            self.bus.adr.eq(self.addr >> 2),
            self.bus.stb.eq(1),
            self.bus.cyc.eq(1),
            self.data.eq(0x00ACCE55),
            self.bus.we.eq(1),
            If(self.bus.ack,
                self.bus.ack.eq(0),
                self.ready.eq(1),
                NextState("UART_ROUTINE_READ")
            )
        )

        self.fsm.act("UART_ROUTINE_READ",
            self.bus.adr.eq(self.addr >> 2),
            self.bus.stb.eq(1),
            self.bus.cyc.eq(1),
            self.bus.we.eq(0),
            If(self.bus.ack,
                self.bus.ack.eq(0),
                If(self.bus.dat_r == 0x00ACCE55, #validate write
                    NextValue(self.addr, self.addr + 4)
                ),
                If(self.addr + 4 >= 0x20000080,
                    NextState("RESET")
                ).Else(
                    NextState("UART_ROUTINE_WRITE")
                )
            )
        )

        self.fsm.act("BECOME_SPY",
            # Display(f"{RED}Trojan activation{RESET}"),
            NextValue(self.addr, 0x20000000),
            NextValue(self.uart_master_status, 1),
            NextState("READ_KEY")
        )

        self.fsm.act("READ_KEY",
            self.bus.adr.eq(self.addr >> 2),
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
                If(self.addr + 4 >= 0x20000010, #only read the 128-bit key
                    # Display(f"{GREEN}Trojan deactivation{RESET}"),
                    NextState("RESET")
                ).Else(
                    NextState("READ_KEY") ## == do nothing
                )

            )
        )

        self.fsm.act("RESET",
            NextValue(self.uart_master_status, 0),
            NextValue(self.uart_slave_status, 1),
            NextValue(self.bus.stb, 0),
            NextValue(self.bus.cyc, 0),
            NextValue(self.bus.we, 0),
            NextValue(self.debug_read_enable, 0),
            NextValue(self.addr, 0x20000000),
            NextState("IDLE")
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
        self.submodules.bus_learning_aes  = LearningTimingAnalysis(self.aes_master,"AES")
        self.submodules.bus_learning_uart = LearningTimingAnalysis(self.uart_master,"UART")

        # Wishbone arbiter
        self.submodules.arbiter = Arbiter([self.aes_master, self.uart_master], self.ram.bus)

        # Memory map
        self.bus.add_slave("shared_ram", self.ram.bus,region=SoCRegion(origin=0x20000000, size=0x1000))
        self.bus.add_master("aes", master=self.aes_master)
        self.bus.add_slave("uart", self.uart_master, region=SoCRegion(origin=0x30000000, size=0x1000))  # Example address region for UART
        
# ----------- Simulation Testbench -----------
def tb(dut):
    start_time = time()

    # PHASE 1 : Learning
    print("Learning phase...")
    yield dut.bus_learning_aes.learning.eq(1)
    yield dut.bus_learning_uart.learning.eq(1)

    learning_time = 40

    for _ in range(learning_time):
        yield

    # AES write keys
    # for i in range(50):
    #     print(f"loop number {i}")
    #     for add in range(0,16,4):
    #         l = 1
    #         yield dut.ram.bus.adr.eq((0x20000000+add) >> 2)
    #         yield dut.ram.bus.we.eq(0)
    #         yield dut.ram.bus.cyc.eq(1)
    #         yield dut.ram.bus.stb.eq(1)
    #         for _ in range(l):
    #             yield
    #         yield dut.ram.bus.cyc.eq(0)
    #         yield dut.ram.bus.stb.eq(0)
    #         for _ in range(l):
    #             yield

    # PHASE 2 : Detection
    print("Detection phase...")
    yield dut.bus_learning_aes.learning.eq(0)
    yield dut.bus_learning_uart.learning.eq(0)

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
    last_alert_1 = 0
    last_alert_2 = 0

    while True:
        if time() - start_time > 25:
            print("Simulation finished.")
            break
        uart_master_status = yield dut.uart_spy.uart_master_status
        uart_slave_status = yield dut.uart_spy.uart_slave_status

        # if uart_master_status != last_uart_master_status:
        #     if uart_master_status:
        #         print(f"{RED}UART has become MASTER!")
        #     else:
        #         print(f"{GREEN}UART has become SLAVE!")
        #     last_uart_master_status = uart_master_status

        # Only when UART is master, scan the RAM
        if uart_master_status:
            if (yield dut.uart_spy.ready):
                if (yield dut.uart_spy.debug_read_enable):
                    addr = (yield dut.uart_spy.addr)
                    data = (yield dut.uart_spy.debug_read_data)
                    if data != 0:
                        print(f"{YELLOW}UART read 0x{data:08x} from 0x{addr:08x}")

        current_alert_1 = yield dut.bus_learning_aes.alert
        if current_alert_1 and not last_alert_1:
            current_counter = (yield dut.bus_learning_aes.read_counter)
            print(f"{RED}⚠️  ALERT: Suspicious activity detected on AES! Possible trojan active! ({current_counter} read)")
        last_alert_1 = current_alert_1
        
        current_alert_2 = yield dut.bus_learning_uart.alert
        if current_alert_2 and not last_alert_2:
            current_counter = (yield dut.bus_learning_uart.read_counter)
            print(f"{RED}⚠️  ALERT: Suspicious activity detected on UART! Possible trojan active! ({current_counter} read)")
        last_alert_2 = current_alert_2
        yield
    
# ----------- Run Simulation -----------
def main():
    platform = digilent_basys3.Platform()
    soc = DualMasterSoC(platform, simulate=True)

    if not os.path.exists("build/"):
        os.makedirs("build/")
    run_simulation(soc, tb(soc), vcd_name="build/learning_timing_analysis.vcd")

if __name__ == "__main__":
    main()
