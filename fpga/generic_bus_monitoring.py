from migen import *
from migen.genlib.fsm import FSM, NextState, NextValue
from migen.sim import run_simulation
from migen.genlib.resetsync import AsyncResetSynchronizer

from litex.soc.integration.soc_core import SoCCore, SoCRegion
from litex.soc.interconnect import wishbone
from litex.soc.interconnect.wishbone import Arbiter, SRAM
from litex_boards.platforms import digilent_basys3
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
            If(self.read_counter >= 2, # dangerous reading size threshold
                self.alert.eq(1)
            ).Else(
                If(~arbiter_bus.cyc & self.last_cyc,
                    # When bus cycle ends, reset read counter
                    self.read_counter.eq(0),
                    #self.alert.eq(0)
                )
            ),

            # Reset read_counter if no stb (i.e., not in active transfer)
            If(~arbiter_bus.stb,
                #self.read_counter.eq(0),
                #self.alert.eq(0)
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
            self.bus.adr.eq(self.addr[2:]),  # this is correct (word address)
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

        # Registres internes pour bus
        self.stb_reg = Signal()
        self.cyc_reg = Signal()
        self.we_reg = Signal()
        self.adr_reg = Signal.like(self.bus.adr)
        self.dat_w_reg = Signal.like(self.bus.dat_w)

        # Variables de temporisation
        self.time_counter = Signal(32)

        # Machine à états
        self.submodules.fsm = FSM(reset_state="IDLE")

        self.fsm.act("IDLE",
            NextValue(self.time_counter, 0),
            If(self.time_counter == 100,
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
            NextValue(self.stb_reg, 1),
            NextValue(self.cyc_reg, 1),
            NextValue(self.we_reg, 0),
            NextValue(self.adr_reg, self.addr[2:]),
            self.debug_read_data.eq(self.data),
            self.debug_read_enable.eq(0),
            If(self.bus.ack,
                self.debug_read_enable.eq(1),
                NextValue(self.data, self.bus.dat_r),
                self.ready.eq(1),
                NextValue(self.addr, self.addr + 4),
                If(self.addr + 4 >= 0x20001000,
                    NextState("WAIT_BEFORE_RESCAN")
                ).Else(
                    NextState("READ_KEY")
                )
            )
        )

        self.fsm.act("WAIT_BEFORE_RESCAN",
            NextValue(self.uart_master_status, 0),  # UART is no longer master
            NextValue(self.uart_slave_status, 1),
            NextValue(self.stb_reg, 0),
            NextValue(self.cyc_reg, 0),
            NextValue(self.we_reg, 0),
            self.debug_read_enable.eq(0),
            If(self.time_counter >= 100,
                NextValue(self.time_counter, 0),
                NextValue(self.addr, 0x20000000),
                NextState("BECOME_MASTER")
            ).Else(
                NextValue(self.time_counter, self.time_counter + 1)
            )
        )

        self.fsm.act("DONE",
            self.ready.eq(1),
            NextValue(self.cyc_reg, 0),
            NextValue(self.stb_reg, 0),
            NextValue(self.we_reg, 0),
        )

        # Liaison des registres internes vers le vrai bus
        self.comb += [
            self.bus.stb.eq(self.stb_reg),
            self.bus.cyc.eq(self.cyc_reg),
            self.bus.we.eq(self.we_reg),
            self.bus.adr.eq(self.adr_reg),
            self.bus.dat_w.eq(self.dat_w_reg)
        ]



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

        self.submodules.aes = AESFromRAM(self.aes_master)
        self.submodules.uart_spy = UARTSpy(self.uart_master)
        self.submodules.bus_monitor = GenericBusMonitor(self.ram.bus)

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

        current_alert = yield dut.bus_monitor.alert
        if current_alert and not last_alert:
            print(f"{RED}⚠️  ALERT: Suspicious activity detected! Possible trojan active!")
        last_alert = current_alert
        yield 



    
def main():
    platform = digilent_basys3.Platform()
    soc = DualMasterSoC(platform, simulate=False)

    alert_led = platform.request("user_led", 0)
    alert_led1 = platform.request("user_led", 1)
    alert_led2 = platform.request("user_led", 2)
    alert_led3 = platform.request("user_led", 3)
    alert_led4 = platform.request("user_led", 4)
    alert_led5 = platform.request("user_led", 5)
    alert_led6 = platform.request("user_led", 6)
    alert_led7 = platform.request("user_led", 7)
    alert_led8 = platform.request("user_led", 8)
    alert_led9 = platform.request("user_led", 9)
    alert_led10 = platform.request("user_led", 10)
    alert_led11 = platform.request("user_led", 11)
    alert_led12 = platform.request("user_led", 12)
    alert_led13 = platform.request("user_led", 13)
    alert_led14 = platform.request("user_led", 14)

    counter = Signal(26)
    led_state = Signal()

    # Si l'alerte est active, on fait clignoter la LED
    soc.sync += [
        counter.eq(counter + 1),

        If(soc.bus_monitor.alert,
            led_state.eq(counter[25])
        )
    ]

    soc.comb += [
        alert_led.eq(led_state),
        alert_led1.eq(led_state),    
        alert_led2.eq(led_state),    
        alert_led3.eq(led_state),    
        alert_led4.eq(led_state),    
        alert_led5.eq(led_state),
        alert_led6.eq(led_state),    
        alert_led7.eq(led_state),    
        alert_led8.eq(led_state),    
        alert_led9.eq(led_state),    
        alert_led10.eq(led_state),    
        alert_led11.eq(led_state),    
        alert_led12.eq(led_state),    
        alert_led13.eq(led_state),    
        alert_led14.eq(led_state),       
    ]
    platform.build(soc)

if __name__ == "__main__":
    main()

