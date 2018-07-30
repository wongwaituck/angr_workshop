#!/usr/bin/env python

# we want to import angr
import angr
# we will be manually setting addresses in memory to be symbolic bitvectors
# so we need claripy
import claripy

# what is the address we wish to reach?
find = 0x080486e4
# what is the address to wish to avoid?
avoid = 0x080486d2 

# let's initialize the angr project with our target binary
proj = angr.Project('./angr_symbolic_stack')

# we need to initialize the symbolic bitvectors to attach to memory
password0 = claripy.BVS('password0', 32)
password1 = claripy.BVS('password1', 32)

# we initialize a blank state where angr will start symbolic execution
# we start right after the call to scanf!
state = proj.factory.blank_state(addr=0x08048694)

# we associate the addresses in memory with the symbolic bitvectors
state.mem[state.regs.ebp - 0xc].int = password0
state.mem[state.regs.ebp - 0x10].int = password1

# we create a symbolic manager to handle the set of possible paths 
# (from the starting state)
simgr = proj.factory.simgr(state)

# we will use a shortcut here: we directly explore from our starting state
# making sure to provide the find/avoid addresses
simgr.explore(find=find, avoid=avoid)

# all satisfiable states are found in as a list in simgr.found
# we simply take the first one (hopefully there's one!)
found = simgr.found[0]

# we need to retrieve the solver from the found state (which has all the necessary constraints)
solver = found.se

# we solve for the concrete values of the bitvectors we initialized above!
pass0 = solver.eval(password0)
pass1 = solver.eval(password1)

print pass0, pass1
