import angr
import claripy

project = angr.Project('./CTF', auto_load_libs=False)

arg1 = claripy.BVS('arg1', 8 * 4)
arg2 = claripy.BVS('arg2', 8 * 5)

state = project.factory.full_init_state(
    args=["./CTF", arg1, arg2]
)

for byte in arg1.chop(8):
    state.solver.add(byte >= 0x20)
    state.solver.add(byte <= 0x7e)

for byte in arg2.chop(8):
    state.solver.add(byte >= 0x20)
    state.solver.add(byte <= 0x7e)

simgr = project.factory.simgr(state)

def is_successful(s):
    return b"You have successfully found the flag 100%" in s.posix.dumps(1)

simgr.explore(find=is_successful)

if simgr.found:
    found = simgr.found[0]
    solution1 = found.solver.eval(arg1, cast_to=bytes)
    solution2 = found.solver.eval(arg2, cast_to=bytes)
    print(f"arg1: {solution1}")
    print(f"arg2: {solution2}")
else:
    print("No solution found.")
