#!/usr/bin/env python

# we want to import angr

# what is the address we wish to reach?
# what is the adderss to wish to avoid?

# let's initialize the angr project with our target binary

# we initialize a starting state where angr will start symbolic execution

# we create a symbolic manager to handle the set of possible paths 
# (from the starting state)

# we will use a shrotcut here: we directly explore from our starting state
# making sure to provide the find/avoid addresses 

# all satisfiable states are found in as a list in simgr.found
# we simply take the first one (hopefully there's one!)

# we dump out the the contents of the stdin from the found state
# note stdin is referenced by the file descriptor 0

