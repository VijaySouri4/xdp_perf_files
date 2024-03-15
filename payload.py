from bcc import BPF

device = "wlp170s0"
b = BPF(src_file="payload.c")
fn = b.load_func("xdp_capture_payload", BPF.XDP)
b.attach_xdp(device, fn, 0)

try:
    b.perf_buffer_poll()
except KeyboardInterrupt:
    pass
