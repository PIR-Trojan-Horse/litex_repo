from migen import *
from migen.genlib.fsm import FSM, NextState
from migen.sim import run_simulation
from litex.soc.integration.soc_core import SoCCore, SoCRegion
from litex.soc.interconnect import wishbone
from litex.soc.interconnect.wishbone import SRAM
from litex_boards.platforms import digilent_basys3
from time import time
import os

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RESET = "\033[0m"

# ----------- Monitored Arbiter -----------
class MonitoredArbiter(Module):
    def __init__(self, masters, target, n_authorized_masters):
        self.masters = masters
        self.target = target
        self.n_authorized_masters = n_authorized_masters
        self.alert = Signal(reset=0)

        self.grant = Signal(max=len(masters))

        reqs = [m.cyc for m in masters]

        # Priorité simple
        self.comb += [
            If(reqs[0], self.grant.eq(0))
            .Elif(reqs[1], self.grant.eq(1))
            .Elif(reqs[2], self.grant.eq(2))
        ]

        for name, size, direction in wishbone._layout:
            if direction == wishbone.DIR_M_TO_S:
                choices = Array(getattr(m, name) for m in masters)
                self.comb += getattr(target, name).eq(choices[self.grant])

        for name, size, direction in wishbone._layout:
            if direction == wishbone.DIR_S_TO_M:
                source = getattr(target, name)
                for i, m in enumerate(masters):
                    dest = getattr(m, name)
                    if name == "ack" or name == "err":
                        self.comb += dest.eq(source & (self.grant == i))
                    else:
                        self.comb += dest.eq(source)

        active_masters = Signal(32)
        self.comb += active_masters.eq(sum([req for req in reqs]))

        self.sync += [
            If(active_masters > self.n_authorized_masters,
                self.alert.eq(1)
            ).Else(
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

        self.time_counter = Signal(32)

        self.fsm.act("IDLE",
            NextValue(self.time_counter, 0),
            If(self.time_counter == 20,
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
                If(self.addr + 4 >= 0x20000014,
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
            If(self.time_counter >= (200),
                NextValue(self.time_counter, 0),
                NextValue(self.addr, 0x20000000),
                NextState("BECOME_MASTER")
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



# ----------- UART Spy (lit depuis RAM) -----------
class RandomComponent(Module):
    def __init__(self, bus):
        self.bus = bus  # Wishbone master interface
        self.ready = Signal(reset=0)
        self.addr = Signal(32)
        self.index = Signal(10)  # 10 bits to count up to 1024 words
        self.data = Signal(32)
        self.debug_read_data = Signal(32)
        self.debug_read_enable = Signal()
        self.random_master_status = Signal()  # Status signal for UART becoming master
        self.random_slave_status = Signal()   # Status signal for UART becoming slave

        self.submodules.fsm = FSM(reset_state="IDLE")

        # Variables de temporisation
        self.time_counter = Signal(32)

        # Machine à états
        self.fsm.act("IDLE",
            NextValue(self.time_counter, 0),
            If(self.time_counter == 5,
                NextState("BECOME_MASTER")
            ).Else(
                NextValue(self.time_counter, self.time_counter + 1)
            )
        )

        self.fsm.act("BECOME_MASTER",
            NextValue(self.addr, 0x20000000),
            NextValue(self.index, 0),
            NextValue(self.random_master_status, 1),
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
                If(self.addr + 4 >= 0x20000100,
                    NextValue(self.addr, 0x20000000),  # Redémarre à 0x20000000
                    NextState("READ_KEY")              # et continue à lire sans jamais dormir
                ).Else(
                    NextState("READ_KEY")
                )
            )
        )

        self.fsm.act("DONE",
            self.ready.eq(1),
            self.bus.cyc.eq(0),
            self.bus.stb.eq(0),
            self.bus.we.eq(0),
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


# ----------- DualMasterSoC avec MonitoredArbiter -----------
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

        # Wishbone arbiter
        self.submodules.arbiter = MonitoredArbiter([
                    self.aes_master, self.uart_master, self.random_master
                ], self.ram.bus, n_authorized_masters=1)

        # Memory map
        self.bus.add_slave("shared_ram", self.ram.bus,region=SoCRegion(origin=0x20000000, size=0x1000))
        self.bus.add_master("aes", master=self.aes_master)
        self.bus.add_slave("uart", self.uart_master, region=SoCRegion(origin=0x30000000, size=0x1000))
        self.bus.add_slave("random", self.random_master, region=SoCRegion(origin=0x30010000, size=0x1000))


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

    for _ in range(5):
        yield
        
    uart_master_status = yield dut.uart_spy.uart_master_status
    last_uart_master_status = uart_master_status
    uart_slave_status = yield dut.uart_spy.uart_slave_status
    
    random_master_status = yield dut.random_component.random_master_status
    last_random_master_status = random_master_status
    random_slave_status = yield dut.random_component.random_slave_status
 
    while True:
        if time() - start_time > 3:
            print("Simulation finished.")
            break
        uart_master_status = yield dut.uart_spy.uart_master_status
        uart_slave_status = yield dut.uart_spy.uart_slave_status

        random_master_status = yield dut.random_component.random_master_status
        random_slave_status = yield dut.random_component.random_slave_status

        if uart_master_status != last_uart_master_status:
            status_message = ""
            if uart_master_status:
                status_message += f"{RED}UART has become MASTER! "
            else:
                status_message += f"{GREEN}UART has become SLAVE! "
            if random_master_status:
                status_message += f"{RED}RANDOM is MASTER! "
            else:
                status_message += f"{GREEN}RANDOM is SLAVE! "
            print(status_message)
            last_uart_master_status = uart_master_status

        if uart_master_status:
            if (yield dut.uart_spy.ready):
                if (yield dut.uart_spy.debug_read_enable):
                    addr = (yield dut.uart_spy.addr)
                    data = (yield dut.uart_spy.debug_read_data)
                    if data != 0:
                        print(f"{YELLOW}UART read 0x{data:08x} from 0x{addr:08x}")

        current_alert = yield dut.arbiter.alert
        if current_alert and not last_alert:
            print(f"{RED}⚠️  ALERT: Suspicious activity detected! Possible trojan active!")
        last_alert = current_alert
        yield 

# ----------- Main -----------
def main():
    platform = digilent_basys3.Platform()
    soc = DualMasterSoC(platform, simulate=True)

    if not os.path.exists("build/"):
        os.makedirs("build/")

    run_simulation(soc, tb(soc), vcd_name="build/arbiter_masters.vcd")

if __name__ == "__main__":
    main()
