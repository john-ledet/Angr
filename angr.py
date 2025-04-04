import angr
import claripy

# Load the binary
project = angr.Project('./find_flag', auto_load_libs=False)

# 1st arg: "john" (4 chars) → 8*4 bits
# 2nd arg: "ledet" (5 chars) → 8*5 bits
arg1 = claripy.BVS('arg1', 8 * 4)
arg2 = claripy.BVS('arg2', 8 * 5)

# Set up initial state with symbolic argv
state = project.factory.full_init_state(
    args=["./find_flag", arg1, arg2]
)

# Add printable constraints
for byte in arg1.chop(8):
    state.solver.add(byte >= 0x20)
    state.solver.add(byte <= 0x7e)

for byte in arg2.chop(8):
    state.solver.add(byte >= 0x20)
    state.solver.add(byte <= 0x7e)

# Simulate and search
simgr = project.factory.simgr(state)

# Check for success string in stdout
def is_successful(s):
    return b"You have successfully found the flag 100%" in s.posix.dumps(1)

simgr.explore(find=is_successful)

# Display result
if simgr.found:
    found = simgr.found[0]
    solution1 = found.solver.eval(arg1, cast_to=bytes)
    solution2 = found.solver.eval(arg2, cast_to=bytes)
    print(f"arg1: {solution1}")
    print(f"arg2: {solution2}")
else:
    print("No solution found.")
