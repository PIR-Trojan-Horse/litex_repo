from migen import *
from litex.soc.integration.soc_core import SoCCore
from litex.gen.sim.core import run_simulation
from litex_boards.platforms import digilent_basys3

class MyNewModule(Module):
  def __init__(self):
    self.sync += Display("Bonjour")

class SoC(SoCCore):
  def __init__(self, platform, simulate=False):
    SoCCore.__init__(self, platform, clk_freq=100e6, cpu_type=None,
                     integrated_rom_size=0x8000,
                     integrated_main_ram_size=0x0000)
    self.submodules.newModule = MyNewModule()

def tb(dut):
  for _ in range(10):
    yield

if __name__ == "__main__":
    platform = digilent_basys3.Platform()
    soc = SoC(platform,True)
    run_simulation(soc,tb(soc))