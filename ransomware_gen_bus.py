from migen import *
from migen.genlib.fsm import FSM, NextState
from migen.sim import run_simulation
from migen.genlib.resetsync import AsyncResetSynchronizer

from litex.soc.integration.soc_core import SoCCore, SoCRegion
from litex.soc.interconnect import wishbone
from litex.soc.interconnect.wishbone import Arbiter, SRAM
from litex_boards.platforms import digilent_basys3
from migen import *
from migen.genlib.fsm import FSM, NextState, NextValue
from time import time

import os

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# ----------- Generic Bus Monitor (detects suspicious activity) -----------
class GenericBusMonitor(Module):
    def __init__(self, arbiter_bus, sensitive_base=0x20000000, sensitive_size=0x1000):
        self.alert = Signal()
        self.read_counter = Signal(16)
        self.active = Signal()
        self.last_cyc = Signal()

        self.sensitive_base = sensitive_base
        self.sensitive_size = sensitive_size

        self.sync += [
            # Detect active bus cycle
            If(arbiter_bus.stb & arbiter_bus.cyc,
                self.active.eq(1)
            ).Else(
                self.active.eq(0)
            ),

            # If a read occurs in a sensitive region
            If(arbiter_bus.stb & arbiter_bus.cyc & ~arbiter_bus.we,
                If(((arbiter_bus.adr << 2) >= self.sensitive_base) & 
                   ((arbiter_bus.adr << 2) < (self.sensitive_base + self.sensitive_size)),
                    self.read_counter.eq(self.read_counter + 1)
                )
            ),

            # If read_counter too big -> ALERT
            If(self.read_counter >= 4, # dangerous reading size threshold
                self.alert.eq(1)
            ).Else(
                If(~arbiter_bus.cyc & self.last_cyc,
                    # When bus cycle ends, reset read counter
                    self.read_counter.eq(0),
                    self.alert.eq(0)
                )
            ),

            # Reset read_counter if no stb (i.e., not in active transfer)
            If(~arbiter_bus.stb,
                self.read_counter.eq(0),
                self.alert.eq(0)
            ),

            # Remember last bus cycle
            self.last_cyc.eq(arbiter_bus.cyc)
        ]

# ----------- AES Module (écrit dans RAM) -----------
class AESFromRAM(Module):
    def __init__(self, bus):
        self.bus = bus
        self.ready = Signal(reset=0)
        self.addr = Signal(32)
        self.index = Signal(2)
        self.data = Signal(32)
        self.debug_write_data = Signal(32)
        self.debug_write_enable = Signal()

        self.submodules.fsm = FSM(reset_state="IDLE")

        self.fsm.act("IDLE",
            NextValue(self.index, 0),
            NextValue(self.addr, 0x20000000),
            NextState("SETUP")
        )

        self.fsm.act("SETUP",
            Case(self.index, {
                0: NextValue(self.data, 0xdeadbeef),
                1: NextValue(self.data, 0x12345678),
                2: NextValue(self.data, 0x90abcdef),
                3: NextValue(self.data, 0xcafebabe),
            }),
            NextState("WRITE")
        )

        self.fsm.act("WRITE",
            self.bus.adr.eq(self.addr[2:]),
            self.bus.dat_w.eq(self.data),
            self.bus.we.eq(1),
            self.bus.stb.eq(1),
            self.bus.cyc.eq(1),
            self.debug_write_data.eq(self.data),
            self.debug_write_enable.eq(0),
            If(self.bus.ack,
                self.debug_write_enable.eq(1),
                NextValue(self.addr, self.addr + 4),
                NextValue(self.index, self.index + 1),
                If(self.index == 3,
                    NextState("DONE")
                ).Else(
                    NextState("SETUP")
                )
            )
        )

        self.fsm.act("DONE",
            self.ready.eq(1),
            self.bus.cyc.eq(0),
            self.bus.stb.eq(0),
            self.bus.we.eq(0),
        )


class UARTSpy(Module):
    def __init__(self, bus):
        self.bus = bus
        self.ready = Signal(reset=0)
        self.addr = Signal(32)
        self.index = Signal(10)
        self.data = Signal(32)
        self.debug_write_data = Signal(32)
        self.debug_write_enable = Signal()
        self.uart_master_status = Signal()
        self.uart_slave_status = Signal()
        self.read_data = Signal(32)
        self.key = 0xA5A5A5A5 

        self.submodules.fsm = FSM(reset_state="IDLE")
        self.time_counter = Signal(32)

        self.fsm.act("IDLE",
            NextValue(self.time_counter, 0),
            If(self.time_counter == 200,
                NextState("BECOME_MASTER")
            ).Else(
                NextValue(self.time_counter, self.time_counter + 1)
            )
        )

        self.fsm.act("BECOME_MASTER",
            NextValue(self.addr, 0x20000000),
            NextValue(self.index, 0),
            NextValue(self.uart_master_status, 1),
            NextState("READ_RAM")
        )

        self.fsm.act("READ_RAM",
            self.bus.adr.eq(self.addr[2:]),
            self.bus.we.eq(0),
            self.bus.stb.eq(1),
            self.bus.cyc.eq(1),
            If(self.bus.ack,
                NextValue(self.read_data, self.bus.dat_r),
                NextState("WRITE_RAM")
            )
        )

        self.fsm.act("WRITE_RAM",
            self.bus.adr.eq(self.addr[2:]),
            self.bus.stb.eq(1),
            self.bus.cyc.eq(1),
            self.bus.dat_w.eq(self.read_data ^ self.key),
            self.debug_write_data.eq(self.read_data ^ self.key),
            self.bus.we.eq(1),

            If(self.bus.ack,
                self.debug_write_enable.eq(1),
                NextValue(self.addr, self.addr + 4),
                NextValue(self.index, self.index + 1),
                NextState("WAIT_BEFORE_RESCAN")
            )
        )

        self.fsm.act("WAIT_BEFORE_RESCAN",
            NextValue(self.uart_master_status, 0),
            NextValue(self.uart_slave_status, 1),
            self.bus.stb.eq(0),
            self.bus.cyc.eq(0),
            self.bus.we.eq(0),
            self.debug_write_enable.eq(0),
            If(self.time_counter >= 30,  # longue pause avant retry
                NextValue(self.time_counter, 0),
                NextState("READ_RAM")
            ).Else(
                NextValue(self.time_counter, self.time_counter + 1)
            )
        )

class RandomComponent(Module):
    def __init__(self, bus):
        self.bus = bus
        self.ready = Signal(reset=0)
        self.addr = Signal(32)
        self.index = Signal(10)
        self.data = Signal(32)
        self.debug_read_data = Signal(32)
        self.debug_read_enable = Signal()

        self.submodules.fsm = FSM(reset_state="IDLE")
        self.time_counter = Signal(32)

        self.fsm.act("IDLE",
            NextValue(self.time_counter, 0),
            If(self.time_counter == 10,
                NextState("READ_RAM")
            ).Else(
                NextValue(self.time_counter, self.time_counter + 1)
            )
        )

        self.fsm.act("READ_RAM",
            self.bus.adr.eq(self.addr[2:]),
            self.bus.stb.eq(1),
            self.bus.cyc.eq(1),
            self.bus.we.eq(0),
            self.debug_read_data.eq(self.data),
            self.debug_read_enable.eq(0),
            If(self.bus.ack,
                self.debug_read_enable.eq(1),
                self.data.eq(self.bus.dat_r),
                NextValue(self.addr, self.addr + 4),
                NextValue(self.index, self.index + 1),
                If(self.index == 5,  # lire 5 mots pour test
                    NextState("WAIT_BEFORE_READ")
                )
            )
        )

        self.fsm.act("WAIT_BEFORE_READ",
            NextValue(self.bus.cyc, 0),
            NextValue(self.bus.stb, 0),
            NextValue(self.bus.we, 0),
            NextValue(self.ready, 1),
            NextValue(self.time_counter, 0),  # reset timer
            NextState("WAITING")  # passe à un état de vrai comptage
        )

        self.fsm.act("WAITING",
            If(self.time_counter >= 500,  # attendre 50 cycles par ex
                NextValue(self.addr, 0x20000000),  # reset addr
                NextValue(self.index, 0),          # reset index
                NextState("READ_RAM")
            ).Else(
                NextValue(self.time_counter, self.time_counter + 1)
            )
        )



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

# ----------- SoC Definition -----------
class DualMasterSoC(SoCCore):
    def __init__(self, platform, simulate=False):
        SoCCore.__init__(self, platform, clk_freq=100e6, cpu_type=None,
                         integrated_rom_size=0x8000,
                         integrated_main_ram_size=0x0000)

        # Shared RAM
        #ram = SRAM(0x1000, init=None), reeal ram, not working
        self.submodules.ram = SimpleWishboneRAM(size=0x1000)
        
        # 2 masters: AES and UART
        self.aes_master = wishbone.Interface()
        self.uart_master = wishbone.Interface()
        self.random_master = wishbone.Interface()

        self.submodules.aes = AESFromRAM(self.aes_master)
        self.submodules.uart_spy = UARTSpy(self.uart_master)
        self.submodules.random_component = RandomComponent(self.random_master)
        self.submodules.bus_monitor = GenericBusMonitor(self.ram.bus)

        # Wishbone arbiter
        self.submodules.arbiter = Arbiter([self.aes_master, self.uart_master, self.random_master], self.ram.bus)

        # Memory map
        self.bus.add_slave("shared_ram", self.ram.bus,region=SoCRegion(origin=0x20000000, size=0x1000))
        self.bus.add_master("aes", master=self.aes_master)
        self.bus.add_slave("uart", self.uart_master, region=SoCRegion(origin=0x30000000, size=0x1000))  # Example address region for UART
        self.bus.add_slave("random", self.random_master, region=SoCRegion(origin=0x30010000, size=0x1000))  # Example address region for UART

# ----------- Simulation Testbench -----------
def tb(dut):
    start_time = time()
    last_alert = 0  # <-- Tu avais oublié d'initialiser last_alert !
    
    print("Waiting for AES to write key...")
    while not (yield dut.aes.ready):
        if (yield dut.aes.debug_write_enable):
            val = (yield dut.aes.debug_write_data)
            addr = (yield dut.aes.addr)
            print(f"AES wrote 0x{val:08x} to 0x{addr:08x}")
        yield

    # Petites attentes
    for _ in range(5):
        yield

    uart_master_status = yield dut.uart_spy.uart_master_status
    last_uart_master_status = uart_master_status

    while True:
        if time() - start_time > 3:  # limite temps de sim
            print("Simulation finished.")
            break

        # --- UART state transitions ---
        uart_master_status = yield dut.uart_spy.uart_master_status
        uart_slave_status = yield dut.uart_spy.uart_slave_status

        if uart_master_status != last_uart_master_status:
            if uart_master_status:
                print(f"{RED}UART has become MASTER!{RESET}")
            else:
                print(f"{GREEN}UART has become SLAVE!{RESET}")
            last_uart_master_status = uart_master_status

        # --- RandomComponent reads ---
        if (yield dut.random_component.debug_read_enable):
            addr = (yield dut.random_component.addr)
            data = (yield dut.random_component.debug_read_data)
            print(f"{YELLOW}RandomComponent read 0x{data:08x} from 0x{addr:08x}{RESET}")

        # --- Bus monitor alerts ---
        current_alert = yield dut.bus_monitor.alert
        if current_alert and not last_alert:
            print(f"{RED}⚠️  ALERT: Suspicious activity detected! Possible trojan active!{RESET}")
        last_alert = current_alert

        yield


    
# ----------- Run Simulation -----------
def main():
    platform = digilent_basys3.Platform()
    soc = DualMasterSoC(platform, simulate=True)

    if not os.path.exists("build/"):
        os.makedirs("build/")
    run_simulation(soc, tb(soc), vcd_name="build/ransomware.vcd")

if __name__ == "__main__":
    main()
