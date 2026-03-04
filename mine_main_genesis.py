import struct, hashlib
from multiprocessing import Process, Queue, cpu_count

MERKLE_BE = "4342838d7a035599595349a37ff9c07969f2698c2dc542949546efbcb9a2cb55"
VERSION = 1
TIME = 1231006505
BITS = 0x1d00ffff

def sha256d(b: bytes) -> bytes:
    return hashlib.sha256(hashlib.sha256(b).digest()).digest()

def bits_to_target_bytes(bits: int) -> bytes:
    exp = bits >> 24
    mant = bits & 0x007fffff
    target_int = mant * (1 << (8*(exp-3)))
    return target_int.to_bytes(32, "big")

TARGET_BE = bits_to_target_bytes(BITS)

PREV_LE = bytes.fromhex("00"*32)
MRKL_LE = bytes.fromhex(MERKLE_BE)[::-1]

PREFIX = struct.pack("<I", VERSION) + PREV_LE + MRKL_LE + struct.pack("<II", TIME, BITS)

def worker(start: int, step: int, out: Queue):
    nonce = start
    while True:
        hdr = PREFIX + struct.pack("<I", nonce)
        h = sha256d(hdr)
        h_be = h[::-1]

        if h_be <= TARGET_BE:
            out.put((nonce, h_be.hex()))
            return

        nonce = (nonce + step) & 0xffffffff


def main():
    n = max(1, cpu_count())

    out = Queue()

    procs = [Process(target=worker, args=(i, n, out), daemon=True) for i in range(n)]

    for p in procs:
        p.start()

    nonce, h = out.get()

    print("MAIN_NONCE", nonce)
    print("MAIN_HASH ", h)

    for p in procs:
        try:
            p.terminate()
        except:
            pass


if __name__ == "__main__":
    main()
