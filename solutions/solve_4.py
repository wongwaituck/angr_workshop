#!/usr/bin/env python

# we want to import angr
import angr
import claripy

# what is the address we wish to reach?
find = 0x804a984
# what is the address to wish to avoid?
avoid = 0x804a972

# what is the function we are emulating?
fn_name = "check_equals_CTUTQFNGHIDEHORG"
keyword = "CTUTQFNGHIDEHORG"

# SimProc
#declare class of your SimProc
class CheckEquals(angr.SimProcedure):
    #overwrite the run function
    def run(self, addr_str_to_check, length):
        #load the string from memory from the current state, self.state
        string = self.state.memory.load(addr_str_to_check, length)
        #return correct value from string comparison
        return claripy.If(string == keyword, claripy.BVV(1, 32), claripy.BVV(0, 32))

# let's initialize the angr project with our target binary
proj = angr.Project('./angr_simproc')

# hook symbol for function
proj.hook_symbol(fn_name, CheckEquals()) 

# we initialize a starting state where angr will start symbolic execution
state = proj.factory.entry_state()

# we create a symbolic manager to handle the set of possible paths 
# (from the starting state)
simgr = proj.factory.simgr(state)

# we will use a shortcut here: we directly explore from our starting state
# making sure to provide the find/avoid addresses
simgr.explore(find=find, avoid=avoid)

# all satisfiable states are found in as a list in simgr.found
# we simply take the first one (hopefully there's one!)
found = simgr.found[0]

# we dump out the the contents of the stdin from the found state
# note stdin is referenced by the file descriptor 0
text = found.posix.dumps(0)
print text
