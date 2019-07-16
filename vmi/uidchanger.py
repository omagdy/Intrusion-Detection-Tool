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

try:
    # Mount the vmifs with the given vm name
    subprocess.call(['umount', '/mnt'], stderr=subprocess.STDOUT)
    subprocess.call(['vmifs', 'name', pvm_name, '/mnt'], stderr=subprocess.STDOUT)
except Exception as e:
    print("Error mounting vm memory image: {}".format(str(e)))
    sys.exit()


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
def get_task(addr_space, pid):

    init_task_addr = addr_space.profile.get_symbol("init_task")
    init_task = obj.Object("task_struct", vm = addr_space, offset = init_task_addr)

    tasks = [] # Using a list for potential support of multiple processes with same PID
    for task in init_task.tasks:

        # print ('task {}, pid {}'.format(task.pid, pid))
        if(task.pid==int(pid)):
            tasks.append(task)
            break

    if not tasks:
        return None
    return tasks[0]

def get_credentails_pa(addr_space, task):

    # Get virtual addresses for task credentials pointers
    real_cred_va = task.real_cred.obj_offset
    cred_va = task.cred.obj_offset

    # Get Physical addresses for task credentials pointers
    real_cred_pa = addr_space.vtop(real_cred_va)
    cred_pa = addr_space.vtop(cred_va)

    return real_cred_pa, cred_pa


# Try catch should be more specific. 
try:
    # Initialize address space (same as a=addrspace() in linux_volshell)
    addr_space=utils.load_as(config)

    # Get target task object
    target_task = get_task(addr_space, target_pid)
    if not target_task:
        print("Task with PID {} not found!".format(target_pid))
        sys.exit()

    # Get a task with root permissions, PID 1 is reliably root always
    task_with_root = get_task(addr_space, 1)

    # Get Physical addresses for root task credentials pointers
    root_real_cred_pa, root_cred_pa = get_credentails_pa(addr_space, task_with_root)

    # Get physical addresses for target task credentials pointers
    target_real_cred_pa, target_cred_pa = get_credentails_pa(addr_space, target_task)

    # Initialize libvmi for writing. Note: the library initialize undesired "[][][]" 
    vmi = Libvmi(pvm_name)

    # Write root "cred" pointer value to "cred" attribute of the target task
    root_cred_pointer = addr_space.read_long_long_phys(root_cred_pa)
    vmi.write_64_pa(target_cred_pa, root_cred_pointer)

    # Write root "real_cred" pointer value to "real_cred" attribute of the target task
    root_real_cred_pointer = addr_space.read_long_long_phys(root_real_cred_pa)
    vmi.write_64_pa(target_real_cred_pa, root_real_cred_pointer)

    print("\nSuccess!")

except Exception as e:
    print("\nFailed to change UID: {}".format(str(e)))