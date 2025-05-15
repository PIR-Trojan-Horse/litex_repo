from litex.soc.integration.soc_core import SoCCore
from litex_boards.platforms import digilent_basys3
from migen import *
from migen.sim import run_simulation

import os

class PRNGComponent(Module):
    def __init__(self,seed = None):
        if seed is None or seed == 0:
            from random import randint
            self.__internal_state = Signal(32,reset=randint(1,(1<<32)-1))
        else:
            self.__internal_state = Signal(32,reset=seed)
        self.random = Signal(32)
        self.__tmp1 = Signal(32)
        self.__tmp2 = Signal(32)
        self.__tmp3 = Signal(32)
        self.__tmp4 = Signal(32)

        self.comb += [
            self.random.eq(self.__internal_state),
            self.__tmp1.eq(self.__internal_state),
            self.__tmp2.eq(self.__tmp1 ^ (self.__tmp1 << 13)),
            self.__tmp3.eq(self.__tmp2 ^ (self.__tmp2 >> 17)),
            self.__tmp4.eq(self.__tmp3 ^ (self.__tmp3 <<  5)),
        ]

        self.sync += [
            # self.__tmp1.eq(self.__internal_state),
            # self.__tmp2.eq(self.__tmp1 ^ (self.__tmp1 << 13)),
            # self.__tmp3.eq(self.__tmp2 ^ (self.__tmp2 >> 17)),
            # self.__tmp4.eq(self.__tmp3 ^ (self.__tmp3 <<  5)),
            self.__internal_state.eq(self.__tmp4),
        ]    

class SocTestPNRG(SoCCore):
    def __init__(self, platform, simulate=False):
        SoCCore.__init__(self, platform, clk_freq=100e6, cpu_type=None,
                         integrated_rom_size=0x8000,
                         integrated_main_ram_size=0x0000)
        self.submodules.pnrg = PRNGComponent()

def tb_pnrg(uut):
    for _ in range(20):
        rand = (yield uut.pnrg.random)
        print(rand)
        yield # /!\ mandatory !? /!\

# ----------- Run Simulation -----------
def main():
    platform = digilent_basys3.Platform()
    soc = SocTestPNRG(platform,True)

    if not os.path.exists("build/"):
        os.makedirs("build/")
    run_simulation(soc,tb_pnrg(soc),vcd_name="build/pnrg.vcd")

if __name__ == "__main__":
    main()
