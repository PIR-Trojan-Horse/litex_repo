from migen import *
from migen.sim import run_simulation

from litex_boards.platforms import digilent_basys3
from litex.soc.integration.soc_core import SoCCore, SoCRegion
from litex.soc.interconnect import wishbone
from litex.soc.interconnect.csr import AutoCSR


# ---------- Blinker Module ----------
class Blinker(Module):
    def __init__(self):
        self.output = Signal()
        counter = Signal(24)
        self.sync += [
            counter.eq(counter + 1),
            self.output.eq(counter[5])  # blink ~3 Hz
        ]


# ---------- AES Simulated Module ----------
class AES_Sim(Module):
    def __init__(self):
        self.key       = Signal(128)
        self.data_in   = Signal(128)
        self.data_out  = Signal(128)
        self.start     = Signal()
        self.ready     = Signal(reset=1)

        count    = Signal(3)
        started  = Signal()

        self.sync += [
            If(self.start & ~started,
                count.eq(5),
                self.ready.eq(0),
                started.eq(1)
            ).Elif(count > 0,
                count.eq(count - 1),
                If(count == 1,
                    self.data_out.eq(self.data_in ^ self.key),
                    self.ready.eq(1),
                    started.eq(0)
                )
            )
        ]


# ---------- AES Wishbone Wrapper ----------
class AESWishbone(Module, AutoCSR):
    def __init__(self):
        self.bus = wishbone.Interface()
        self.submodules.aes = AES_Sim()

        key_parts = [Signal(32) for _ in range(4)]
        data_parts = [Signal(32) for _ in range(4)]

        self.comb += [
            self.aes.key.eq(Cat(*key_parts)),
            self.aes.data_in.eq(Cat(*data_parts))
        ]

        self.sync += [
            self.bus.ack.eq(0),
            self.aes.start.eq(0),

            If(self.bus.cyc & self.bus.stb & ~self.bus.ack,
                If(self.bus.we,
                    Case(self.bus.adr, {
                        0x00 >> 2: key_parts[0].eq(self.bus.dat_w),
                        0x04 >> 2: key_parts[1].eq(self.bus.dat_w),
                        0x08 >> 2: key_parts[2].eq(self.bus.dat_w),
                        0x0C >> 2: key_parts[3].eq(self.bus.dat_w),

                        0x10 >> 2: data_parts[0].eq(self.bus.dat_w),
                        0x14 >> 2: data_parts[1].eq(self.bus.dat_w),
                        0x18 >> 2: data_parts[2].eq(self.bus.dat_w),
                        0x1C >> 2: data_parts[3].eq(self.bus.dat_w),

                        0x20 >> 2: self.aes.start.eq(1),
                    })
                ).Else(
                    Case(self.bus.adr, {
                        0x30 >> 2: self.bus.dat_r.eq(self.aes.data_out[:32]),
                        0x34 >> 2: self.bus.dat_r.eq(self.aes.data_out[32:64]),
                        0x38 >> 2: self.bus.dat_r.eq(self.aes.data_out[64:96]),
                        0x3C >> 2: self.bus.dat_r.eq(self.aes.data_out[96:128]),
                        0x40 >> 2: self.bus.dat_r.eq(self.aes.ready),
                    })
                ),
                self.bus.ack.eq(1)
            )
        ]


# ---------- UART Spy Wishbone Wrapper ----------
class UARTSpyWishbone(Module):
    def __init__(self, aes_module):
        self.bus = wishbone.Interface()
        self.aes = aes_module

        self.sync += [
            self.bus.ack.eq(0),
            If(self.bus.cyc & self.bus.stb & ~self.bus.ack & ~self.bus.we,
                Case(self.bus.adr, {
                    0x00 >> 2: self.bus.dat_r.eq(self.aes.key[0:32]),
                    0x04 >> 2: self.bus.dat_r.eq(self.aes.key[32:64]),
                    0x08 >> 2: self.bus.dat_r.eq(self.aes.key[64:96]),
                    0x0C >> 2: self.bus.dat_r.eq(self.aes.key[96:128]),
                    0x10 >> 2: self.bus.dat_r.eq(self.aes.data_out[0:32]),
                    0x14 >> 2: self.bus.dat_r.eq(self.aes.data_out[32:64]),
                    0x18 >> 2: self.bus.dat_r.eq(self.aes.data_out[64:96]),
                    0x1C >> 2: self.bus.dat_r.eq(self.aes.data_out[96:128]),
                }),
                self.bus.ack.eq(1)
            )
        ]


# ---------- SoC Definition ----------
class BlinkerSoC(SoCCore):
    def __init__(self, platform, simulate=False):
        SoCCore.__init__(
            self, platform, clk_freq=100e6, cpu_type=None,
            integrated_rom_size=0x8000,
            integrated_main_ram_size=0x8000
        )

        self.submodules.blinker = Blinker()
        led = platform.request("user_led", 0)
        self.comb += led.eq(self.blinker.output)

        self.submodules.aes_wb = AESWishbone()
        self.bus.add_slave("aes", self.aes_wb.bus,
                           region=SoCRegion(origin=0x20000000, size=0x1000))

        self.submodules.uart_spy = UARTSpyWishbone(self.aes_wb.aes)
        self.bus.add_slave("uartspy", self.uart_spy.bus,
                           region=SoCRegion(origin=0x21000000, size=0x1000))


# ---------- Testbench ----------
def tb(dut):
    def wb_write(bus, addr, val):
        yield bus.adr.eq(addr >> 2)
        yield bus.dat_w.eq(val)
        yield bus.we.eq(1)
        yield bus.stb.eq(1)
        yield bus.cyc.eq(1)
        yield
        yield bus.stb.eq(0)
        yield bus.cyc.eq(0)
        yield

    def wb_read(bus, addr):
        yield bus.adr.eq(addr >> 2)
        yield bus.we.eq(0)
        yield bus.stb.eq(1)
        yield bus.cyc.eq(1)
        yield
        val = (yield bus.dat_r)
        yield bus.stb.eq(0)
        yield bus.cyc.eq(0)
        yield
        return val

    # Write key
    key = [0xdeadbeef, 0x12345678, 0x90abcdef, 0xcafebabe]
    for i, val in enumerate(key):
        yield from wb_write(dut.aes_wb.bus, 0x00 + i * 4, val)

    # Write data
    data = [0x01234567, 0x89abcdef, 0x01234567, 0x89abcdef]
    for i, val in enumerate(data):
        yield from wb_write(dut.aes_wb.bus, 0x10 + i * 4, val)

    # Start AES
    yield from wb_write(dut.aes_wb.bus, 0x20, 1)

    # Wait until ready
    for i in range(20):
        ready = yield from wb_read(dut.aes_wb.bus, 0x40)
        print(f"[{i}] AES ready = {ready}")
        if ready:
            out = []
            for j in range(4):
                val = yield from wb_read(dut.aes_wb.bus, 0x30 + j * 4)
                out.append(val)
            print("    AES data_out =", "".join(f"{v:08x}" for v in reversed(out)))
            break
        yield

    # UARTSpy reads key[0:32]
    key_low = yield from wb_read(dut.uart_spy.bus, 0x00)
    print(f"UART spy read key[0:32] = 0x{key_low:08x}")

    # UARTSpy reads data_out[0:32]
    data_low = yield from wb_read(dut.uart_spy.bus, 0x10)
    print(f"UART spy read data_out[0:32] = 0x{data_low:08x}")


# ---------- Main ----------
def main():
    platform = digilent_basys3.Platform()
    soc = BlinkerSoC(platform, simulate=True)
    run_simulation(soc, tb(soc), vcd_name="simulation.vcd")

if __name__ == "__main__":
    main()
