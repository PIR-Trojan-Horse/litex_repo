from migen import *
from migen.sim import run_simulation

# Définir StopSimulation soi-même (Migen ne l'exporte pas)
class StopSimulation(Exception):
    pass

class SimSoC(Module):
    def __init__(self):
        # Crée le domaine d'horloge "cd_sys" avec reset
        self.clock_domains.cd_sys = ClockDomain("sys")

        # Signals internes
        self.counter = Signal(24)
        self.blinker = Signal()

        # Logique synchrone
        self.sync.sys += [
            self.counter.eq(self.counter + 1),
            self.blinker.eq(self.counter[4])  # Blink lent
        ]

def tb(dut):
    # Appliquer un reset initial
    yield dut.cd_sys.rst.eq(1)
    yield
    yield dut.cd_sys.rst.eq(0)
    
    for i in range(100):
        yield
        print(f"counter: {(yield dut.counter)} blinker: {(yield dut.blinker)}")
    
    raise StopSimulation()

if __name__ == "__main__":
    dut = SimSoC()
    run_simulation(dut, tb(dut), vcd_name="sim.vcd")
    print("✅ Simulation terminée.")
