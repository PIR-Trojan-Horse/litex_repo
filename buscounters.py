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
CYAN = "\033[36m"
RESET = "\033[0m"

# ----------- Generic Bus Monitor (detects suspicious activity) -----------
class BusUtilizationMonitor(Module):
    def __init__(self, bus,
                 read_threshold=1000,
                 write_threshold=500,
                 sample_cycles=100_000):
        # Alert goes high if either reads or writes exceed their thresholds
        self.alert       = Signal()
        self.sample_done = Signal()

        # counters & sample timer
        self.cycle_cnt   = Signal(32)
        self.read_count  = Signal(32)
        self.write_count = Signal(32)

        # Snapshot registers for samples comparison
        self.last_read   = Signal(32)
        self.last_write  = Signal(32)

        # latched deltas
        self.delta_read  = Signal(32)
        self.delta_write = Signal(32)

        # each clock, update counters
        self.sync += [
            # timer
               
            self.cycle_cnt.eq(self.cycle_cnt + 1),
            # self.read_count.eq(self.read_count + 1),

            # read cycle?
            If(bus.stb & bus.cyc & ~bus.we,# | self.cycle_cnt < 21,
                self.read_count.eq(self.read_count + 1)
            ),

            # write cycle?
            If(bus.stb & bus.cyc & bus.we,
                self.write_count.eq(self.write_count + 1)
            ),
        ]

        # each sample :: compare diffs and reset
        self.sync += [
            If(self.cycle_cnt >= sample_cycles,
                # update deltas
                self.delta_read.eq(self.read_count  - self.last_read),
                self.delta_write.eq(self.write_count - self.last_write),
                # then tell tb() that sampling is done
                self.sample_done.eq(1),
                # if more read or write + threshold than last time -> go in alert
                If(self.delta_read > read_threshold,
                    self.alert.eq(1)
                ).Elif(self.delta_write > write_threshold,
                    self.alert.eq(1)
                ).Else(
                    self.alert.eq(0)
                ),

                # snapshot current counts
                self.last_read.eq(self.read_count),
                self.last_write.eq(self.write_count),

                # reset timer for next sample
                self.cycle_cnt.eq(0),
            ).Else(
                # reset all flags
                self.sample_done.eq(0),
                self.alert.eq(0)
            )
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
        #activate it less frequently
        # self.throttle_factor = throttle_factor
        # self.throttle_cnt = Signal(max=throttle_factor)
        self.trojan_activation = Signal()
        
        
        self.bus = bus  # Wishbone master interface
        self.ready = Signal(reset=0)
        self.addr = Signal(32)
        self.index = Signal(10)  # 10 bits to count up to 1024 words
        self.data = Signal(32)
        self.debug_read_data = Signal(32)
        self.debug_read_enable = Signal()
        self.uart_master_status = Signal()  # Status signal for UART becoming master
        self.uart_slave_status = Signal()   # Status signal for UART becoming slave
        self.activate = Signal() 

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
            If(self.activate,
                self.trojan_activation.eq(1),
                NextState("BECOME_MASTER"),
                # first check our throttle counter
                # If(self.throttle_cnt == 0,
                #     self.trojan_activation.eq(1),
                #     NextState("BECOME_MASTER")
                # ).Else(
                #     # skip this activation, just decrement throttle_cnt
                #     NextValue(self.throttle_cnt, self.throttle_cnt - 1),
                #     self.trojan_activation.eq(0),
                #     NextState("IDLE")
                # )
            )
        )



        self.fsm.act("BECOME_MASTER",
            # NextValue(self.throttle_cnt, throttle_factor - 1),
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
                If(self.addr + 4 >= 0x20000008,
                    self.trojan_activation.eq(0),
                    NextState("WAIT_BEFORE_RESCAN")
                ).Else(
                    self.trojan_activation.eq(1),
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
            # FIXME: TIME ACTIVATION TROJAN
            If(self.time_counter >= 1000,
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
        # self.submodules.bus_learning = LearningBusMonitor(self.ram.bus)
        
        # Wishbone arbiter
        self.submodules.arbiter = Arbiter([self.aes_master, self.uart_master], self.ram.bus)

        self.submodules.bus_counter = BusUtilizationMonitor(
            bus=self.ram.bus,
            read_threshold=20,     # params to learn ? maybe
            write_threshold=20,    # params to learn ? maybe
            sample_cycles=200
        )
        self.add_constant("COUNTER_ALERT", self.bus_counter.alert)


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
    # for _ in range(5):
    #     yield

    # Laisser le temps à AES d'écrire les clés
    # for _ in range(50):
    #     addr_bus = dut.ram.bus.adr
    #     cyc = dut.ram.bus.cyc
    #     stb = dut.ram.bus.stb
    #     we = dut.ram.bus.we

    #     # Read at 0x20000000
    #     yield addr_bus.eq((0x20000000) >> 2)
    #     yield we.eq(0)
    #     yield cyc.eq(1)
    #     yield stb.eq(1)
    #     yield
    #     yield cyc.eq(0)
    #     yield stb.eq(0)
    #     yield
    #     # Read at 0x20000004
    #     yield addr_bus.eq((0x20000004) >> 2)
    #     yield we.eq(0)
    #     yield cyc.eq(1)
    #     yield stb.eq(1)
    #     yield
    #     yield cyc.eq(0)
    #     yield stb.eq(0)
    #     yield
    #     # Read at 0x20000008
    #     yield addr_bus.eq((0x20000008) >> 2)
    #     yield we.eq(0)
    #     yield cyc.eq(1)
    #     yield stb.eq(1)
    #     yield
    #     yield cyc.eq(0)
    #     yield stb.eq(0)
    #     yield
    #     # Read at 0x2000000c
    #     yield addr_bus.eq((0x2000000c) >> 2)
    #     yield we.eq(0)
    #     yield cyc.eq(1)
    #     yield stb.eq(1)
    #     yield
    #     yield cyc.eq(0)
    #     yield stb.eq(0)
    #     yield

    # Activer l’espion UART
    yield dut.uart_spy.activate.eq(1)

    uart_master_status = yield dut.uart_spy.uart_master_status
    last_uart_master_status = uart_master_status  # Store the initial state
    uart_slave_status = yield dut.uart_spy.uart_slave_status

    # Monitor UART master/slave transitions
    uart_master_status = yield dut.uart_spy.uart_master_status
    last_uart_master_status = uart_master_status
    last_alert = 0
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
            # ✨ NEW: Monitor each time `ready` goes high
            if (yield dut.uart_spy.ready):
                if (yield dut.uart_spy.debug_read_enable):
                    addr = (yield dut.uart_spy.addr)
                    data = (yield dut.uart_spy.debug_read_data)
                    if data != 0:
                        print(f"{YELLOW}UART read 0x{data:08x} from 0x{addr:08x}")

        # current_alert = yield dut.bus_learning.alert
        # if current_alert and not last_alert:
            # print(f"{RED}⚠️  ALERT: Suspicious activity detected! Possible trojan active!")
        if (yield dut.bus_counter.alert):
            print(f"{RED}⚠️ ALERT: Suspicious activity detected! Possible trojan active! ⚠️ Bus-Utilization Spike!")
        # last_alert = current_alert
        if (yield dut.uart_spy.trojan_activation):
            print(f"{PURPLE}Trojan is reading...")
            
        if (yield dut.bus_counter.sample_done):
            # compute deltas in TB (you could also expose them as signals)
            dr = (yield dut.bus_counter.delta_read)
            dw = (yield dut.bus_counter.delta_write)
            print(f"{CYAN}🔍 Sample done: reads={dr}, writes={dw}, alert={ (yield dut.bus_counter.alert) }")

        
        yield 



    
def main():
    platform = digilent_basys3.Platform()
    soc = DualMasterSoC(platform, simulate=True)

    if not os.path.exists("build/"):
        os.makedirs("build/")
    run_simulation(soc, tb(soc), vcd_name="build/busCounters.vcd")

if __name__ == "__main__":
    main()

