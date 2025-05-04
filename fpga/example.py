from migen import *
from litex_boards.platforms import digilent_basys3

class LEDBlinker(Module):
    def __init__(self, platform):
        led = platform.request("user_led", 0)
        counter = Signal(26)
        self.sync += counter.eq(counter + 1)
        self.comb += led.eq(counter[25])

def main():
    platform = digilent_basys3.Platform()
    dut = LEDBlinker(platform)
    platform.build(dut)

if __name__ == "__main__":
    main()
