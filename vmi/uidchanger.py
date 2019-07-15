import subprocess
import time
import argparse
import sys
import os
import socket
from libvmi import Libvmi

# Parse required input arguments
parser = argparse.ArgumentParser(
    description='UidChanger arguments')
parser.add_argument('-n','--name', help='Input target VM name "one-<id>"', required=True)
parser.add_argument('-p','--pid', help='Input target process id "PID"', required=True)
args = parser.parse_args()
# print (args)
pvm_name = args.name
target_pid = args.pid

# Mount the vmifs with the given vm name
subprocess.call(['umount', '/mnt'], stderr=subprocess.STDOUT)
subprocess.call(['vmifs', 'name', pvm_name, '/mnt'], stderr=subprocess.STDOUT)


sys.path.append("/usr/src/volatility")
## Define vmifs image and profile for volatility
sys.argv = [sys.argv[0], "-f", "/mnt/mem", "--profile", "LinuxDebian8x64"]

# Configure volatility
import volatility.conf as conf
import volatility.utils as utils

config = conf.ConfObject()

import volatility.obj as obj
import volatility.addrspace as addrspace
import volatility.registry as registry
registry.PluginImporter()
registry.register_global_options(config, addrspace.BaseAddressSpace)

# Function to get a task object for given PID using volatility profile and address space
def get_task(a, p, pid):

    init_task_addr = p.get_symbol("init_task")
    init_task = obj.Object("task_struct", vm = a, offset = init_task_addr)

    tasks = [] # Using a list for potential support of multiple processes with same PID
    for task in init_task.tasks:

        # print ('task {}, pid {}'.format(task.pid, pid))
        if(task.pid==int(pid)):
            tasks.append(task)
            break

    if not tasks:
        return None
    return tasks[0]

try:

    # Initialize address space (same as a=addrspace() in linux_volshell)
    a=utils.load_as(config)
    p=a.profile

    # Get target task object
    target_task = get_task(a, p, target_pid)
    if(not target_task):
        print("Task with PID {} not found!")
        sys.exit()

    # Get a task with root permissions, PID 1 is reliably root always
    task_with_root = get_task(a, p, 1)

    # Get virtual addresses for root task credentials pointers
    root_real_cred_va = task_with_root.real_cred.obj_offset
    root_cred_va = task_with_root.cred.obj_offset

    # Get Physical addresses for root task credentials pointers
    root_real_cred_pa = a.vtop(root_real_cred_va)
    root_cred_pa = a.vtop(root_cred_va)

    # Get virtual addresses for target task credentials pointers
    target_real_cred_va = target_task.real_cred.obj_offset
    target_cred_va = target_task.cred.obj_offset

    # Get physical addresses for root task credentials pointers
    target_real_cred_pa = a.vtop(target_real_cred_va)
    target_cred_pa = a.vtop(target_cred_va)

    # Initialize libvmi for writing
    vmi = Libvmi(pvm_name)

    # Write root "cred" pointer value to "cred" attribute of the target task
    root_cred_pointer = a.read_long_long_phys(root_cred_pa)
    vmi.write_64_pa(target_cred_pa, root_cred_pointer)

    # Write root "real_cred" pointer value to "real_cred" attribute of the target task
    root_real_cred_pointer = a.read_long_long_phys(root_real_cred_pa)
    vmi.write_64_pa(target_real_cred_pa, root_real_cred_pointer)

    print("\nSuccess!")

except Exception as e:
    print("\nFailed to change UID: {}".format(str(e)))