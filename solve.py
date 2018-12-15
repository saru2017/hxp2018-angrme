import angr

p = angr.Project('./angrme')
main_addr = p.loader.main_object.get_symbol('main').rebased_addr
addr_success = main_addr + 4631
addr_fail = main_addr + 4656
sim = p.factory.simgr()
sim.explore(find=addr_success, avoid=addr_fail)
s = sim.found[0]
print(s.posix.dumps(0))
