import subprocess
import time
import sys
import paramiko
import argparse


PROCESSES = { 
	'linux_psaux':'Processes',
	'linux_pstree':'Process Trees',
	'linux_netstat':'Network Connections',
	'linux_lsmod':'Modules',
	'linux_hidden_modules':'Hidden Modules',
	}
PROCESSES_PREVIOUS_STATUS = {'linux_psaux':[], 'linux_pstree':[], 'linux_netstat':[], 'linux_lsmod':[], 'linux_hidden_modules':[]}

SSH_PROCESSES = {
	'ps aux': 'Processes',
	'pstree': 'Process Trees',
	'lsmod':'Modules',
	'netstat -tap':'Network Connections:',
	}
SSH_PROCESSES_PREVIOUS_STATUS = {'ps aux':[], 'pstree':[], 'lsmod':[], 'netstat -tap':[]}
# SSH_PROCESSES_REPEATED_STATUS = SSH_PROCESSES_PREVIOUS_STATUS


def command_over_ssh(process):
	ssh = paramiko.SSHClient()
	ssh.set_missing_host_key_policy(
	    paramiko.AutoAddPolicy())
	ssh.connect('192.168.13.66', username='root', password='123456')
	stdin, stdout, stderr = ssh.exec_command(process)
	output = stdout.readlines()
	ssh.close()
	return output

def run_process(process, ssh=False):
	if ssh:
		return command_over_ssh(process)
	else:
		return (subprocess.check_output(['/usr/src/volatility/vol.py', '-f', '/mnt/mem', '--profile=LinuxDebian8x64', process], stderr=subprocess.STDOUT)).split('\n')


# def status_comparison(previous_entries, current_entries):
	# missing_entries=[]
	# new_entries=[]
	# for entry in previous_entries:
	# 	if entry not in current_entries:
	# 		missing_entries.append(entry)
	# for entry in current_entries:
	# 	if entry not in previous_entries:
	# 		new_entries.append(entry)
	# return missing_entries, new_entries

def status_comparison(previous_entries, current_entries):
	prev_entries = set(previous_entries)
	curr_entries = set(current_entries)
	return list(prev_entries-curr_entries), list(curr_entries-prev_entries)


def fill_initial_entries(ssh=False):

	if ssh:
		C_PROCESSES = SSH_PROCESSES
		C_PROCESSES_PREVIOUS_STATUS = SSH_PROCESSES_PREVIOUS_STATUS
	else:
		C_PROCESSES = PROCESSES
		C_PROCESSES_PREVIOUS_STATUS = PROCESSES_PREVIOUS_STATUS

	for process in C_PROCESSES.keys():
		intial_entry = run_process(process, ssh)
		C_PROCESSES_PREVIOUS_STATUS[process] = intial_entry


def print_change_in_entries(ssh=False):

	if ssh:
		C_PROCESSES_PREVIOUS_STATUS = SSH_PROCESSES_PREVIOUS_STATUS
		C_PROCESSES = SSH_PROCESSES
	else:
		C_PROCESSES_PREVIOUS_STATUS = PROCESSES_PREVIOUS_STATUS
		C_PROCESSES = PROCESSES

	for process in C_PROCESSES.keys():
		current_status = run_process(process, ssh)
		missing_entries, new_entries = status_comparison(C_PROCESSES_PREVIOUS_STATUS[process], current_status)
		print("{}: ".format(C_PROCESSES[process]))
		if missing_entries or new_entries:
			for entry in missing_entries:
				print('-  '+entry)
			for entry in new_entries:
				print('+  '+entry)
			C_PROCESSES_PREVIOUS_STATUS[process] = current_status
		# else:
		# 	print("No changes in {} detected!".format(C_PROCESSES[process]))


# Parse required input arguments
parser = argparse.ArgumentParser(
    description='UidChanger arguments')
parser.add_argument('-n','--name', help='Input target VM name "one-<id>"', required=True)
parser.add_argument('-r','--runinterval', help='Wait time between repeated command executions (seconds)', required=True, type=int)
args = parser.parse_args()
# print (args)
pvm_id = args.name
RUNINTERVAL = args.runinterval

if pvm_id == 'ssh':
	fill_initial_entries(True)
	while(1):
		print_change_in_entries(True)
		time.sleep(RUNINTERVAL)

try:
    # Mount the vmifs with the given vm name
    subprocess.call(['umount', '/mnt'], stderr=subprocess.STDOUT)
    subprocess.call(['vmifs', 'name', pvm_id, '/mnt'], stderr=subprocess.STDOUT)
except Exception as e:
    print("Error mounting vm memory image: {}".format(str(e)))
    sys.exit()

fill_initial_entries()
while(1):
	print_change_in_entries()
	# print("\nWating for {} seconds..\n".format(RUNINTERVAL))
	time.sleep(RUNINTERVAL)