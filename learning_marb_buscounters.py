from migen import *
from migen.genlib.fsm import FSM, NextState, NextValue
from migen.sim import run_simulation
from migen.genlib.resetsync import AsyncResetSynchronizer

from litex.soc.integration.soc_core import SoCCore, SoCRegion
from litex.soc.interconnect import wishbone
from litex.soc.interconnect.wishbone import Arbiter, SRAM
from litex_boards.platforms import digilent_basys3
from time import sleep, time

import os

# Petit Analyseur Sympathique Très Inefficace Sincèrement

RED = "\033[91m"
RED_BG = "\033[101m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[36m"
PURPLE = "\033[35m"
RESET = "\033[0m"

# ----------- Generic Bus Monitor (detects suspicious activity) -----------
class BusUtilizationMonitor(Module):
    def __init__(self, bus,
                #  default_read=0,
                #  default_write=50,
                arbiter,
                margin = 1,
                sample_cycles=100_000):
        self.learn = Signal()
        n_masters = len(arbiter.masters)
        self.n_masters = n_masters
        self.arbiter = arbiter
        # margin = len(arbiter.masters)
        # Alert goes high if either reads or writes exceed their thresholds
        self.alert       = Signal()
        self.alert_pulse = Signal()
        self.sample_done = Signal()
        
        self.read_threshold  = Signal(32)
        self.write_threshold = Signal(32)
        
        # Seuils master-spécifiques
        self.read_thresholds  = Array([Signal(32, reset=0) for _ in range(n_masters)])
        self.write_thresholds = Array([Signal(32, reset=0) for _ in range(n_masters)])

        # Compteurs master-spécifiques
        self.read_counts  = Array([Signal(32, reset=0) for _ in range(n_masters)])
        self.write_counts = Array([Signal(32, reset=0) for _ in range(n_masters)])

        # Snapshots master-spécifiques
        self.last_reads  = Array([Signal(32, reset=0) for _ in range(n_masters)])
        self.last_writes = Array([Signal(32, reset=0) for _ in range(n_masters)])

        # Deltas master-spécifiques
        self.delta_reads  = Array([Signal(32, reset=0) for _ in range(n_masters)])
        self.delta_writes = Array([Signal(32, reset=0) for _ in range(n_masters)])
        
        # self.read_min_threshold  = Signal(32)
        # self.write_min_threshold = Signal(32)
        # self.write_threshold.eq(default_write)

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
        
        self.zero = Signal()

        # each clock, update counters
        # self.sync += [
        #     # timer
        #     self.cycle_cnt.eq(self.cycle_cnt + 1),
        #     # self.read_count.eq(self.read_count + 1),

        #     # read cycle?
        #     If(bus.stb & bus.cyc & ~bus.we,# | self.cycle_cnt < 21,
        #         self.read_count.eq(self.read_count + 1)
        #     ),

        #     # write cycle?
        #     If(bus.stb & bus.cyc & bus.we,
        #         self.write_count.eq(self.write_count + 1)
        #     )
        # ]
        
        self.sync += [
            self.cycle_cnt.eq(self.cycle_cnt + 1),
            If(bus.stb & bus.cyc & ~bus.we,
               # lecture : on cible read_counts[grant]
               self.read_counts[self.arbiter.grant].eq(
                   self.read_counts[self.arbiter.grant] + 1),
            ),
            If(bus.stb & bus.cyc & bus.we,
               # écriture
               self.write_counts[self.arbiter.grant].eq(
                   self.write_counts[self.arbiter.grant] + 1),
            )
        ]

        # each sample :: compare diffs and reset
        # self.sync += [
        #     # self.zero.eq(1), & (self.last_read > self.zero)
        #     If(self.cycle_cnt >= sample_cycles,
        #         # Display("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
        #         If (self.read_count > self.last_read,   self.delta_read.eq(self.read_count  -  self.last_read)).Else(self.delta_read.eq(self.last_read  -  self.read_count)),
        #         If (self.write_count > self.last_write, self.delta_write.eq(self.write_count - self.last_write)).Else(self.delta_write.eq(self.last_write - self.write_count)),
        #         # self.delta_read.eq(self.read_count  - self.last_read),
        #         # self.delta_write.eq(self.write_count - self.last_write),
        #         self.sample_done.eq(1),
                
        #         If(self.learn,
        #             If(((self.delta_read + margin) > self.read_threshold & (self.last_read > 0) & (self.read_count > 0)), self.read_threshold.eq(self.delta_read + margin)),
        #             If(((self.delta_write + margin) > self.write_threshold & (self.last_write > 3) & (self.write_count > 3)), self.write_threshold.eq(self.delta_write + margin)),
        #             self.cycle_cnt.eq(0),
        #             # self.last_read.eq(self.read_count),
        #             # self.last_write.eq(self.write_count),
        #         ).Else(# update deltas
        #             # self.delta_read.eq(self.read_count  - self.last_read),
        #             # self.delta_write.eq(self.write_count - self.last_write),
        #             # then tell tb() that sampling is done
        #             # if more read or write + threshold than last time -> go in alert
        #             If(self.delta_read > self.read_threshold,
        #                 self.alert_pulse.eq(1),
        #                 self.alert.eq(1)
        #             ).Elif(self.delta_write > self.write_threshold,
        #                 self.alert_pulse.eq(1),
        #                 self.alert.eq(1)
        #             ).Else(
        #                 self.alert.eq(0)
        #             ),
        #             # self.sample_done.eq(1),


        #         ),
                
        #         # snapshot current counts
        #         self.last_read.eq(self.read_count),
        #         self.last_write.eq(self.write_count),
        #         self.read_count.eq(0),
        #         self.write_count.eq(0),
                
        #         # reset timer for next sample
        #         self.cycle_cnt.eq(0)
        #     ).Else(
        #         # reset all flags
        #         self.alert_pulse.eq(0),
        #         self.sample_done.eq(0),
        #         self.alert.eq(0)
        #     )
        # ]
        
    
        self.sync += [
            If(self.cycle_cnt >= sample_cycles,
                #calcul du delta pour le maître actif
                If(self.read_counts[self.arbiter.grant]
                   > self.last_reads[self.arbiter.grant],
                   self.delta_reads[self.arbiter.grant]
                       .eq(self.read_counts[self.arbiter.grant]
                           - self.last_reads[self.arbiter.grant])
                ).Else(
                   self.delta_reads[self.arbiter.grant]
                       .eq(self.last_reads[self.arbiter.grant]
                           - self.read_counts[self.arbiter.grant])
                ),

                If(self.write_counts[self.arbiter.grant]
                   > self.last_writes[self.arbiter.grant],
                   self.delta_writes[self.arbiter.grant]
                       .eq(self.write_counts[self.arbiter.grant]
                           - self.last_writes[self.arbiter.grant])
                ).Else(
                   self.delta_writes[self.arbiter.grant]
                       .eq(self.last_writes[self.arbiter.grant]
                           - self.write_counts[self.arbiter.grant])
                ),

                # signal de fin d'échantillon
                self.sample_done.eq(1),

                If(self.learn,
                    # mise à jour du seuil lecture si delta + marge > ancien seuil
                    If((self.delta_reads[self.arbiter.grant] + margin)
                       > self.read_thresholds[self.arbiter.grant],
                       self.read_thresholds[self.arbiter.grant]
                           .eq(self.delta_reads[self.arbiter.grant] + margin)
                    ),
                    # idem pour l'écriture
                    If((self.delta_writes[self.arbiter.grant] + margin)
                       > self.write_thresholds[self.arbiter.grant],
                       self.write_thresholds[self.arbiter.grant]
                           .eq(self.delta_writes[self.arbiter.grant] + margin)
                    ),
                ).Else(
                    # déclenchement d'alerte si dépassement du seuil propre au maître
                    If(self.delta_reads[self.arbiter.grant]
                       > self.read_thresholds[self.arbiter.grant],
                       self.alert.eq(1), self.alert_pulse.eq(1)
                    ).Elif(self.delta_writes[self.arbiter.grant]
                       > self.write_thresholds[self.arbiter.grant],
                       self.alert.eq(1), self.alert_pulse.eq(1)
                    ).Else(
                       self.alert.eq(0)
                    )
                ),

                # FIXME: oiezjfoiezjfeozijfz
                # on mémorise les compteurs avant remise à zéro
                # NextValue(self.last_reads[self.arbiter.grant],
                #           self.read_counts[self.arbiter.grant]),
                self.last_reads[self.arbiter.grant].eq(self.read_counts[self.arbiter.grant]),
                # NextValue(self.last_writes[self.arbiter.grant],
                #           self.write_counts[self.arbiter.grant]),
                self.last_writes[self.arbiter.grant].eq(self.write_counts[self.arbiter.grant]),

                # remise à zéro de **tous** les compteurs pour repartir à neuf
                *[self.read_counts[i].eq(0) for i in range(n_masters)],
                *[self.write_counts[i].eq(0) for i in range(n_masters)],

                # et reset du timer
                # NextValue(self.cycle_cnt, 0),
                self.cycle_cnt.eq(0)
            ).Else(
                # hors échantillon, on baisse les flags
                # NextValue(self.sample_done, 0),
                # NextValue(self.alert_pulse, 0),
                # NextValue(self.alert, 0),
                self.alert_pulse.eq(0),
                self.sample_done.eq(0),
                self.alert.eq(0)
            )
        ]


class MonitoredArbiter(Module):
    def __init__(self, masters, target, n_authorized_masters):
        self.masters = masters
        self.target = target
        self.n_authorized_masters = n_authorized_masters
        self.alert = Signal(reset=0)
        self.alert_count = Signal(32, reset=0)
        self.no_alert_count = Signal(32, reset=0)

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
                self.alert.eq(1),
                self.alert_count.eq(self.alert_count + 1),
            ).Else(
                self.alert.eq(0),
                self.no_alert_count.eq(self.no_alert_count + 1),
            )
        ]


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


# ----------- AES Module (écrit dans RAM) -----------
class AESFromRAM(Module):
    def __init__(self, bus, loop=True):
        self.bus = bus
        self.ready = Signal(reset=0)
        
        self.loop  = loop
        
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
            # pulse ready high for one cycle
            NextValue(self.ready, 1),
            # deassert bus
            self.bus.stb.eq(0),
            self.bus.cyc.eq(0),
            self.bus.we.eq(0),

            # if looping requested, restart
            If(self.loop,
                # NextValue(self.ready, 0),
                NextState("IDLE")
            )
        )


# ----------- UART Spy (lit depuis RAM) -----------

class UARTSpy(Module):
    def __init__(self, bus):
        # 0 = read / 1 = write
        self.toggle = Signal(reset=0)
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
                NextState("BECOME_MASTER_R"),
            )
        )



        self.fsm.act("BECOME_MASTER_R",
            NextValue(self.addr, 0x20000000),
            NextValue(self.index, 0),
            NextValue(self.uart_master_status, 1),
            self.trojan_activation.eq(1),
            NextState("READ_KEY")
        )
        
        self.fsm.act("BECOME_MASTER_W",
            NextValue(self.addr, 0x20000000),
            NextValue(self.index, 0),
            NextValue(self.uart_master_status, 1),
            self.trojan_activation.eq(1),
            NextState("WRITE_ZERO")
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
                    NextValue(self.toggle, 1), 
                    NextState("WAIT_BEFORE_RESCAN_W"),
                ).Else(
                    #self.trojan_activation.eq(1),
                    NextState("READ_KEY")
                )
            )
            
        )
        
        # État d'écriture qui remet la mémoire à zéro
        self.fsm.act("WRITE_ZERO",
            NextValue(self.stb_reg, 1),
            NextValue(self.cyc_reg, 1),
            NextValue(self.we_reg, 1),
            NextValue(self.adr_reg, self.addr[2:]),
            NextValue(self.dat_w_reg, 0),        # on écrit 0
            self.debug_read_enable.eq(0),
            If(self.bus.ack,
                self.debug_read_enable.eq(1),
                NextValue(self.ready, 1),
                # NextValue(self.toggle, 0),        # on repasse en lecture
                NextValue(self.addr, self.addr + 4),
                # NextState("WAIT_BEFORE_RESCAN_R"),
                
                # self.debug_read_enable.eq(1),
                NextValue(self.data, self.bus.dat_r),
                # self.ready.eq(1),
                # NextValue(self.addr, self.addr + 4),
                If(self.addr + 4 >= 0x20000108,
                    self.trojan_activation.eq(0),
                    NextValue(self.toggle, 0), 
                    NextState("WAIT_BEFORE_RESCAN_R"),
                ).Else(
                    #self.trojan_activation.eq(1),
                    NextState("WRITE_ZERO")
                )
            )
        )

        self.fsm.act("WAIT_BEFORE_RESCAN_W",
            NextValue(self.uart_master_status, 0),  # UART is no longer master
            NextValue(self.uart_slave_status, 1),
            NextValue(self.stb_reg, 0),
            NextValue(self.cyc_reg, 0),
            NextValue(self.we_reg, 0),
            self.debug_read_enable.eq(0),
            # FIXME: TIME ACTIVATION TROJAN
            If(self.time_counter >= 150,
                NextValue(self.time_counter, 0),
                NextValue(self.addr, 0x20000000),
                NextState("BECOME_MASTER_W")
            ).Else(
                NextValue(self.time_counter, self.time_counter + 1)
            )
        )
        
        self.fsm.act("WAIT_BEFORE_RESCAN_R",
            NextValue(self.uart_master_status, 0),  # UART is no longer master
            NextValue(self.uart_slave_status, 1),
            NextValue(self.stb_reg, 0),
            NextValue(self.cyc_reg, 0),
            NextValue(self.we_reg, 0),
            self.debug_read_enable.eq(0),
            # FIXME: TIME ACTIVATION TROJAN
            If(self.time_counter >= 300,
                NextValue(self.time_counter, 0),
                NextValue(self.addr, 0x20000000),
                NextState("BECOME_MASTER_R")
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
        self.random_master = wishbone.Interface()

        self.submodules.aes = AESFromRAM(self.aes_master)
        self.submodules.uart_spy = UARTSpy(self.uart_master)
        # self.submodules.bus_learning = LearningBusMonitor(self.ram.bus)
        self.submodules.random_component = RandomComponent(self.random_master)
        
        # Wishbone arbiter
        # self.submodules.arbiter = Arbiter([self.aes_master, self.uart_master], self.ram.bus) # Wishbone arbiter
        self.submodules.arbiter = MonitoredArbiter([
                    self.aes_master, self.uart_master, self.random_master
                ], self.ram.bus, n_authorized_masters=1)

        self.submodules.bus_counter = BusUtilizationMonitor(
            bus=self.ram.bus,
            # [self.aes_master, self.uart_master, self.random_master]
            arbiter=self.arbiter,
            sample_cycles=20,
        )
        self.add_constant("COUNTER_ALERT", self.bus_counter.alert)


        # Memory map
        self.bus.add_slave("shared_ram", self.ram.bus,region=SoCRegion(origin=0x20000000, size=0x1000))
        self.bus.add_master("aes", master=self.aes_master)
        self.bus.add_slave("uart", self.uart_master, region=SoCRegion(origin=0x30000000, size=0x1000))  # Example address region for UART
        self.bus.add_slave("random", self.random_master, region=SoCRegion(origin=0x30010000, size=0x1000))
# ----------- Simulation Testbench -----------
def tb(dut):
    print("Petit Analyseur Sympathique Très Inefficace Sincèrement is starting...")
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
        
    # PHASE 1 : Apprentissage
    print("Phase d'apprentissage...")
    # yield dut.bus_counter.learn.eq(1)
    
    # Simulate reading the AES key written in RAM
    # for _ in range(5):
    #     yield

    # Laisser le temps à AES d'écrire les clés
    for _ in range(1):
        addr_bus = dut.ram.bus.adr
        cyc = dut.ram.bus.cyc
        stb = dut.ram.bus.stb
        we = dut.ram.bus.we

        # Read at 0x20000000
        yield addr_bus.eq((0x20000000) >> 2)
        yield we.eq(0)
        yield cyc.eq(1)
        yield stb.eq(1)
        yield
        yield cyc.eq(0)
        yield stb.eq(0)
        yield
        # Read at 0x20000004
        yield addr_bus.eq((0x20000004) >> 2)
        yield we.eq(0)
        yield cyc.eq(1)
        yield stb.eq(1)
        yield
        yield cyc.eq(0)
        yield stb.eq(0)
        yield
        # Read at 0x20000008
        yield addr_bus.eq((0x20000008) >> 2)
        yield we.eq(0)
        yield cyc.eq(1)
        yield stb.eq(1)
        yield
        yield cyc.eq(0)
        yield stb.eq(0)
        yield
        # Read at 0x2000000c
        yield addr_bus.eq((0x2000000c) >> 2)
        yield we.eq(0)
        yield cyc.eq(1)
        yield stb.eq(1)
        yield
        yield cyc.eq(0)
        yield stb.eq(0)
        yield
    # sleep(2)
    
    
    # yield dut.bus_counter.learn.eq(1)
    for _ in range(200):
        if (yield dut.bus_counter.sample_done):
            yield dut.bus_counter.learn.eq(1)
            
            drs = []
            for i in range(dut.bus_counter.n_masters):
                drs.append((yield dut.bus_counter.delta_reads[i]))
            dws = []
            for i in range(dut.bus_counter.n_masters):
                dws.append((yield dut.bus_counter.delta_writes[i]))
            rts = []
            for i in range(dut.bus_counter.n_masters):
                rts.append((yield dut.bus_counter.read_thresholds[i]))
            wts = []
            for i in range(dut.bus_counter.n_masters):
                wts.append((yield dut.bus_counter.write_thresholds[i]))

            # enfin, afficher
            print(f"{GREEN}LEARNING… window read={drs} write={dws} | "
                f"current: rt={rts} wt={wts}{RESET}")
        yield
    
    # while True:
    #     if time() - start_time > 5:
    #         break
    #     else:
    #         if (yield dut.bus_counter.sample_done):
    #             dr    = (yield dut.bus_counter.delta_read)
    #             dw    = (yield dut.bus_counter.delta_write)
    #             tdr    = (yield dut.bus_counter.read_threshold)
    #             tdw    = (yield dut.bus_counter.write_threshold)
    #             print(f"{GREEN}LEARNING.... current= r:{dr};w:{dw} | max= r:{tdr};w:{tdw}{RESET}")
    #     yield 
    
    # PHASE 2 : Détection (désactive apprentissage)
    print("Phase de détection...")
    yield dut.bus_counter.learn.eq(0)

    # Activer l’espion UART
    yield dut.uart_spy.activate.eq(1)

    uart_master_status = yield dut.uart_spy.uart_master_status
    last_uart_master_status = uart_master_status  # Store the initial state
    uart_slave_status = yield dut.uart_spy.uart_slave_status

    # Monitor UART master/slave transitions
    uart_master_status = yield dut.uart_spy.uart_master_status
    last_uart_master_status = uart_master_status
    # last_alert = 0
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

        if (yield dut.uart_spy.trojan_activation):
            print(f"{PURPLE}Trojan is active...")
            
        if (yield dut.bus_counter.sample_done):
            # dr    = (yield dut.bus_counter.delta_read)
            # dw    = (yield dut.bus_counter.delta_write)
            # lw    = (yield dut.bus_counter.last_write)
            # # cw    = (yield dut.bus_counter.write_count)
            # lr    = (yield dut.bus_counter.last_read)
            # # cr    = (yield dut.bus_counter.read_count)
            # tdr    = (yield dut.bus_counter.read_threshold)
            # tdw    = (yield dut.bus_counter.write_threshold)
            lrs = []
            for i in range(dut.bus_counter.n_masters):
                lrs.append((yield dut.bus_counter.last_reads[i]))
            lws = []
            for i in range(dut.bus_counter.n_masters):
                lws.append((yield dut.bus_counter.last_writes[i]))
            drs = []
            for i in range(dut.bus_counter.n_masters):
                drs.append((yield dut.bus_counter.delta_reads[i]))
            dws = []
            for i in range(dut.bus_counter.n_masters):
                dws.append((yield dut.bus_counter.delta_writes[i]))
            rts = []
            for i in range(dut.bus_counter.n_masters):
                rts.append((yield dut.bus_counter.read_thresholds[i]))
            wts = []
            for i in range(dut.bus_counter.n_masters):
                wts.append((yield dut.bus_counter.write_thresholds[i]))
            alert = (yield dut.bus_counter.alert)
            if alert:
                print(f"{RED}⚠️ ALERT: Suspicious activity detected! Possible Trojan active! ⚠️ Bus-Utilization Spike!")
                # print(f"{RED_BG}{CYAN}🔍 Sample done: reads={dr}({cr}-{lr}), writes={dw}({cw}-{lw}), alert={alert}, EXPECTED: deltaAuthorized r:{tdr};w:{tdw}{RESET}")
                # print(f"{RED_BG}{CYAN}🔍 Sample done: reads={dr}, writes={dw}, alert={alert}, EXPECTED: deltaAuthorized r:{tdr};w:{tdw}{RESET}")
                print(f"{RED_BG}{CYAN}🔍 Sample done: reads={lrs}(Δ={drs}), writes={lws}(Δ={dws}), alert={alert}, EXPECTED: deltaAuthorized r:{rts};w:{wts}{RESET}")
            else:
                # print(f"{CYAN}🔍 Sample done: reads={dr}({cr}-{lr}), writes={dw}({cw}-{lw}), alert={alert} {GREEN}Exp: r:{tdr};w:{tdw}{RESET}")
                # print(f"{CYAN}🔍 Sample done: reads={dr}, writes={dw}, alert={alert} {GREEN}Exp: r:{tdr};w:{tdw}{RESET}")
                print(f"{CYAN}🔍 Sample done: reads={lrs}(Δ={drs}), writes={lws}(Δ={dws}), alert={alert} {GREEN}Exp: r:{rts};w:{wts}{RESET}")

        yield 



    
def main():
    platform = digilent_basys3.Platform()
    soc = DualMasterSoC(platform, simulate=True)

    if not os.path.exists("build/"):
        os.makedirs("build/")
    run_simulation(soc, tb(soc), vcd_name="build/busMarbCounters.vcd")

if __name__ == "__main__":
    main()

