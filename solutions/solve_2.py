#!/usr/bin/env python

# we want to import angr
import angr

# what is the address we wish to reach?
find = 0x80485DD
# what is the address to wish to avoid?
avoid = [0x80485A8, 0x80485EF]

# let's initialize the angr project with our target binary
proj = angr.Project('./angr_avoid')

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
