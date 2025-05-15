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
from prng_component import PRNGComponent
from litex.soc.cores.timer import Timer
from litex.soc.cores.uart import UART
from litex.soc.cores.dma import WishboneDMAReader, WishboneDMAWriter
from litex.soc.interconnect.csr import CSRStorage, CSRStatus, AutoCSR

import os

RED = "\033[91m\033[1m"   # Rouge + gras
GREEN = "\033[92m\033[1m"  # Vert + gras
YELLOW = "\033[93m\033[1m" # Jaune + gras
ORANGE = "\033[38;5;208m\033[1m"  # Orange + gras
BLUE = "\033[94m\033[1m"  # Bleu + gras
PURPLE = "\033[35m\033[1m"  # Violet + gras
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

        self.true_positives = Signal(32)
        self.false_positives = Signal(32)
        self.false_negatives = Signal(32)
        self.true_negatives = Signal(32)

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
        self.active_intent = Signal()

        self.submodules.fsm = FSM(reset_state="IDLE")

        # Variables de temporisation
        self.time_counter = Signal(32)

        # Machine à états
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
            NextValue(self.active_intent, 1),
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
            NextValue(self.active_intent, 0),
            NextValue(self.uart_master_status, 0),  # UART is no longer master
            NextValue(self.uart_slave_status, 1),
            NextValue(self.bus.stb, 0),
            NextValue(self.bus.cyc, 0),
            NextValue(self.bus.we, 0),
            NextValue(self.debug_read_enable, 0),
            If(self.time_counter >= (50),  # about ~10s
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


class LegitTrafficGenerator(Module):
    def __init__(self, bus, prng, base_addr=0x20000000, span=0x1000, access_interval=20):
        self.bus = bus
        self.read_enable = Signal()
        self.write_enable = Signal()
        self.addr = Signal(32)
        self.data = Signal(32)
        self.counter = Signal(8, reset=0)
        self.random_val = Signal(32)
        self.burst_count = Signal(4)
        self.op_write = Signal()
        self.bus_stb = Signal()
        self.bus_cyc = Signal()

        self.index = Signal(32, reset=2)

        self.comb += [
            bus.stb.eq(self.bus_stb),
            bus.cyc.eq(self.bus_cyc),
            self.random_val.eq(prng.random)
        ]

        self.submodules.fsm = FSM(reset_state="IDLE")

        self.fsm.act("IDLE",
            NextValue(self.bus_stb, 0),
            NextValue(self.bus_cyc, 0),

            If(self.counter == 0,
                NextValue(self.index, self.index + 1),
                If(self.random_val[0:7] < 25,
                    NextValue(self.burst_count, 6),
                ).Else(
                    NextValue(self.burst_count, 2 + self.random_val[7:9])
                ),
                NextValue(self.op_write, 0),
                NextValue(self.addr, base_addr + ((self.random_val[9:21] << 2) & (span - 4))),
                NextState("ACCESS")
            ).Else(
                NextValue(self.counter, self.counter - 1)
            )
        )

        self.fsm.act("ACCESS",
            self.bus.adr.eq(self.addr[2:]),
            self.bus.we.eq(self.op_write),
            self.bus.dat_w.eq(self.random_val),
            NextValue(self.bus_stb, 1),
            NextValue(self.bus_cyc, 1),
            If(self.bus.ack,
                If(self.op_write,
                    self.write_enable.eq(1)
                ).Else(
                    self.read_enable.eq(1)
                ),
                If(self.burst_count > 1,
                    NextValue(self.addr, self.addr + 4),
                    NextValue(self.burst_count, self.burst_count - 1),
                    NextState("PAUSE")
                ).Else(
                    NextValue(self.counter, access_interval),
                    NextValue(self.bus_stb, 0),
                    NextValue(self.bus_cyc, 0),
                    NextState("IDLE")
                )
            )
        )

        self.fsm.act("PAUSE",
            NextValue(self.bus_stb, 0),
            NextValue(self.bus_cyc, 0),
            NextState("ACCESS")
        )


class TimerNoise(Module):
    def __init__(self, bus, timer_base_addr=0xe0000000):
        self.bus = bus
        self.addr = Signal(32, reset=timer_base_addr)
        self.counter = Signal(8)
        self.read_enable = Signal()
        self.burst_count = Signal(4)

        # LFSR 3 bits pour générer pseudo-aléatoire entre 1 et 8
        self.lfsr = Signal(3, reset=0b101)
        lfsr_next = Signal(3)
        self.comb += lfsr_next.eq(Cat(self.lfsr[1] ^ self.lfsr[2], self.lfsr[0:2]))  # feedback polynomial

        self.sync += self.lfsr.eq(lfsr_next)

        self.submodules.fsm = FSM(reset_state="IDLE")

        self.fsm.act("IDLE",
            #self.bus.stb.eq(0),                     
            If(self.counter == 0,
                NextValue(self.burst_count, self.lfsr + 1),  # 1 à 8
                NextState("READ")
            ).Else(
                NextValue(self.counter, self.counter - 1)
            )
        )

        self.fsm.act("READ",
            self.bus.adr.eq(self.addr[2:]),  # toujours même adresse
            self.bus.cyc.eq(1),
            self.bus.stb.eq(1),
            self.bus.we.eq(0),
            If(self.bus.ack,
                self.read_enable.eq(1),
                If(self.burst_count > 1,
                    NextValue(self.burst_count, self.burst_count - 1)
                ).Else(
                    NextValue(self.counter, 40),  # pause fixe ou pseudo-aléatoire
                    NextState("IDLE")
                )
            ).Else(
                self.read_enable.eq(0)
            )
        )



class MyWishboneDMAReader(WishboneDMAReader):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        # Sauvegarde explicite des CSR (nécessaire pour accès externe)
        self.base_storage   = self.get_csrs("base")[0]
        self.length_storage = self.get_csrs("length")[0]
        self.start_re       = self.get_csrs("start")[0]
        self.done_status    = self.get_csrs("done")[0]

class DMAReaderNoise(Module):
    def __init__(self, reader_csr):
        self.counter = Signal(8)
        self.submodules.fsm = FSM(reset_state="IDLE")

        # Signaux de configuration pour le CSR
        self.base_storage_signal = Signal(32)  # Signal temporaire pour base_storage
        self.length_storage_signal = Signal(32)  # Signal temporaire pour length_storage
        self.start_re_signal = Signal()  # Signal temporaire pour start_re

        # État initial : attente avant de déclencher
        self.fsm.act("IDLE",
            If(self.counter == 0,
                NextState("CONFIGURE")
            ).Else(
                NextValue(self.counter, self.counter - 1)
            )
        )

        # Configuration du transfert DMA
        self.fsm.act("CONFIGURE",
            self.base_storage_signal.eq(0x20001000),  # Adresse de lecture
            self.length_storage_signal.eq(0x10),      # Nombre d’octets à lire
            self.start_re_signal.eq(1),                # Déclenchement
            NextValue(self.counter, 10),               # Réduit la durée de l'attente
            NextState("WAIT")
        )

        # Connexion combinatoire des signaux aux registres CSR
        self.comb += [
            reader_csr.base_storage.storage.eq(self.base_storage_signal),
            reader_csr.length_storage.storage.eq(self.length_storage_signal),
            reader_csr.start_re.storage.eq(self.start_re_signal)
        ]

        # Attente de la fin du transfert
        # Modification : Accès à done_status en utilisant .status ou un autre attribut approprié
        self.fsm.act("WAIT",
            If(reader_csr.done_status.storage,  # Accès direct au registre CSR
                NextState("IDLE")
            ).Else(
                NextValue(self.counter, self.counter - 1)  # Diminue progressivement
            )
        )


class UARTNoise(Module):
    def __init__(self, uart, delay=50000):  # Le paramètre delay contrôle le délai
        self.submodules.fsm = FSM(reset_state="IDLE")
        self.char = Signal(8, reset=0x41)  # ASCII 'A'
        self.counter = Signal(32, reset=0)  # Compteur interne pour gérer le délai
        self.delay = delay  # Délai pour la fréquence de transmission

        # FSM pour gérer l'envoi du caractère
        self.fsm.act("IDLE",
            If(uart._txempty.status,  # Vérifie si le FIFO de transmission est vide
                NextState("SEND")
            )
        )

        self.fsm.act("SEND",
            # Vérifie si le compteur a atteint le délai
            If(self.counter == self.delay,
                uart.tx_fifo.sink.valid.eq(1),  # Le FIFO est prêt à envoyer
                uart.tx_fifo.sink.payload.eq(self.char),  # Donnée à envoyer
                NextState("WAIT"),
                self.counter.eq(0)  # Réinitialiser le compteur
            ).Else(
                # Sinon, incrémente le compteur
                self.counter.eq(self.counter + 1)
            )
        )

        self.fsm.act("WAIT",
            # Attendre avant de revenir à l'état IDLE
            NextState("IDLE")
        )


# ----------- SoC Definition -----------
class DualMasterSoC(SoCCore):
    def __init__(self, platform, simulate=False):
        SoCCore.__init__(self, platform,
                         clk_freq=100e6,
                         cpu_type="None",  # ou "picorv32"
                         integrated_rom_size=0x8000,
                         integrated_main_ram_size=0x2000,
                         ident="LiteX SoC with Monitor")


        self.submodules.ram = wishbone.SRAM(0x1000,init=[0 for _ in range(0x1000>>2)])
        self.add_memory_region("ram", 0x20000000, 0x1000)
        self.bus.add_slave("ram", self.ram.bus)
                
        # 2 masters: AES and UART
        self.aes_master = wishbone.Interface()
        self.uart_master = wishbone.Interface()
        self.submodules.prng = PRNGComponent(seed=0x12345678)
        self.legit_master = wishbone.Interface()


        self.submodules.aes = AESFromRAM(self.aes_master)
        self.submodules.uart_spy = UARTSpy(self.uart_master)
        self.submodules.bus_monitor = GenericBusMonitor(self.ram.bus,sensitive_base=0x20000000,sensitive_size=0x10)
        self.submodules.legit_traffic = LegitTrafficGenerator(self.legit_master,prng=self.prng,base_addr=0x20001000,span=0x1000,access_interval=2)
        # Wishbone arbiter
        self.submodules.arbiter = Arbiter([self.aes_master, self.uart_master, self.legit_master], self.ram.bus)
    
        # Memory map
        self.bus.add_master("aes", master=self.aes_master)
        self.bus.add_slave("uart", self.uart_master, region=SoCRegion(origin=0x30000000, size=0x1000))

        self.submodules.timer0 = Timer()
        self.add_csr("timer0")
        #self.submodules.reader = MyWishboneDMAReader(bus=self.ram.bus, with_csr=True)        
        #self.add_csr("reader")
        #self.submodules.writer = WishboneDMAWriter(bus=self.ram.bus, with_csr=True)        
        #self.add_csr("writer")
        #self.submodules.uart0 = UART()
        #self.add_csr("uart0")
        #
        self.submodules.timer_noise = TimerNoise(self.ram.bus)
        #self.submodules.dma_noise = DMAReaderNoise(self.reader)        
        #self.submodules.uart_noise = UARTNoise(self.uart0)


# ----------- Simulation Testbench -----------
def tb(dut):
    start_time = time()
    true_positives = 0
    false_positives = 0
    false_negatives = 0
    true_negatives = 0

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
    nb_activations = 0
    while time() - start_time < 3:
        uart_master_status = yield dut.uart_spy.uart_master_status
        uart_slave_status = yield dut.uart_spy.uart_slave_status

        if uart_master_status != last_uart_master_status:
            if uart_master_status:
                print(f"{RED}[TROJAN] Activation!")
            last_uart_master_status = uart_master_status

        is_trojan_active = yield dut.uart_spy.active_intent
        is_alert_triggered = yield dut.bus_monitor.alert

        if is_alert_triggered and is_trojan_active:
            true_positives += 1
        elif is_alert_triggered and not is_trojan_active:
            false_positives += 1
        elif not is_alert_triggered and is_trojan_active:
            false_negatives += 1
        else:
            true_negatives += 1
        if (yield dut.legit_traffic.read_enable):
            print(f"{GREEN}[LEGIT] read addr {(yield dut.legit_traffic.addr):08x}")

        if (yield dut.legit_traffic.write_enable):
            print(f"{GREEN}[LEGIT] wrote data {(yield dut.legit_traffic.data):08x} at {(yield dut.legit_traffic.addr):08x}")

        if (yield dut.timer_noise.read_enable):
            print(f"{ORANGE}[TIMER] performing action")
        yield 
    print(f"{PURPLE}\n=== Detection Statistics ===")
    print(f"True Positives:  {true_positives}")
    print(f"False Positives: {false_positives}")
    print(f"False Negatives: {false_negatives}")
    print(f"True Negatives:  {true_negatives}")
    precision = true_positives / (true_positives + false_positives)
    print(f"Precision: {precision:.2f}")



    
# ----------- Run Simulation -----------
def main():
    platform = digilent_basys3.Platform()
    soc = DualMasterSoC(platform, simulate=True)
    
    if not os.path.exists("build/"):
        os.makedirs("build/")
    run_simulation(soc, tb(soc), vcd_name="build/generic_analysis_bus.vcd")

if __name__ == "__main__":
    main()
