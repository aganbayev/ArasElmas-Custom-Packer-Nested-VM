from z3 import *

solver = Solver()
KEY_LEN = 30
key = [BitVec(f'k_{i}', 32) for i in range(KEY_LEN)]

# Restrict to printable ASCII characters
for i in range(KEY_LEN):
    solver.add(
        Or(
            And(key[i] >= ord('A'), key[i] <= ord('Z')),
            And(key[i] >= ord('a'), key[i] <= ord('z')),
            And(key[i] >= ord('0'), key[i] <= ord('9')),
            key[i] == ord('-'),
            key[i] == ord(' ')
        )
    )

# Fixed Prefix
prefix = b"gamers "
for i in range(len(prefix)):
    solver.add(key[i] == prefix[i])

# ARX Bit-Rotate Transformation
def FUN_1400043c0(val):
    return RotateLeft(val, 5) ^ 0x5A5A5A5A

local_14 = BitVecVal(0xA5A5A5A5, 32)
for local_18 in range(KEY_LEN):
    term = (local_18 + 3) * key[local_18]
    local_14 = FUN_1400043c0(local_14 + term)

# Target Hash Match
EXPECTED_HASH = 0x43743434 
solver.add(local_14 == EXPECTED_HASH)

if solver.check() == sat:
    m = solver.model()
    res = [m[key[i]].as_long() for i in range(KEY_LEN)]
    print(f"[★] RECOVERED KEY: {bytes(res).decode('ascii')}")