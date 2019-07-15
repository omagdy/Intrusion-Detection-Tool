import os
import signal
import subprocess
import time
import sys
import paramiko
import re
import ast
import time
import signal

GLOBAL_SUB_PROCESS = ''
TRACKED_USERS=[]

class SuspectedUser:

	def __init__(self, uid, sshd_pid='0', bash_pid='0', name='', ip='', bash_clone_pid=[]):
		self.name = name
		self.uid = uid
		self.sshd_pid = sshd_pid
		self.bash_pid = bash_pid
		self.ip = ip
		self.bash_clone_pid=bash_clone_pid
		self.prev_buf_was_output=True

	def print_login(self):
		print('User '+self.name+' is sshing to the Wordpress from '+self.ip+'. His uid is '+str(self.uid)+'. His bash pid is '+str(self.bash_pid))
	
	def print_logout(self):
		print('User '+str(self.name)+' with bash pid '+str(self.bash_pid)+' sshed out of the Wordpress.')

	def write_to_log_file(self, bash_data):
		here = os.path.dirname(os.path.realpath(__file__))
		subdir = "logs"
		filename = self.name+'-'+self.ip+'-'+str(self.bash_pid)+'.txt'
		filepath = os.path.join(here, subdir, filename)
		f=open(filepath,"a")
		f.write(bash_data)
		f.close()

	def create_log_file(self):
		here = os.path.dirname(os.path.realpath(__file__))
		subdir = "logs"
		filename = self.name+'-'+self.ip+'-'+str(self.bash_pid)+'.txt'
		filepath = os.path.join(here, subdir, filename)
		f=open(filepath,"a")
		f.write('New ssh connection from '+self.ip+'\n')
		f.close()
		

def exit_the_tool(sig, frame):
	stop_libvmtrace()
	sys.exit(0)


def check_for_user_logout(trace):
	if trace['syscall_nr']!=61 or trace['proc_name']!='sshd':
		return
	ending_bash_pid = trace['return_value']
	uid = trace['uid']
	for u in TRACKED_USERS:
		if u.uid == uid and u.bash_pid==ending_bash_pid:
			TRACKED_USERS.remove(u)
			u.print_logout()
			del u
			return

def check_for_new_sshed_users(trace):
	if trace['syscall_nr']!=59:
		return
	if trace['path']=="/bin/bash":
		uid = trace['uid']
		pid = (trace['pid'])
		env = trace['env']
		for x in env:
			if 'USER=' in x:
				name = re.search('=(.+)$', x).group(1)
			if 'SSH_CLIENT=' in x:
				ip = re.search('=(.+)$', x).group(1)
		user = SuspectedUser(uid, name=name, ip=ip, bash_pid=pid)
		TRACKED_USERS.append(user)
		user.print_login()
		user.create_log_file()


def check_for_user_input(trace):
	if 'buf' not in trace:
		return
	if trace['proc_name']=="bash" and trace['syscall_nr']==1:
		uid = trace['uid']
		pid = trace['pid']
		fd = trace['fd']
		for u in TRACKED_USERS:
			if u.uid == uid and ((u.bash_pid==pid and fd in [1,2]) or (pid in u.bash_clone_pid)):
				line = trace['buf'].decode('unicode-escape')
				if trace['size']==1 and u.prev_buf_was_output and trace['buf']!="\\u0008\\u001b[K":
					u.write_to_log_file('> '+line)
					sys.stdout.write('> '+line)
					sys.stdout.flush()
					u.prev_buf_was_output=False
				elif trace['size']==1 and not u.prev_buf_was_output and trace['buf']!="\\u0008\\u001b[K":
					u.write_to_log_file(line)
					sys.stdout.write(line)
					sys.stdout.flush()
				elif not u.prev_buf_was_output and trace['buf']=="\\u0008\\u001b[K":
					u.write_to_log_file(line)
					sys.stdout.write(line)
					sys.stdout.flush()					
				else:
					u.write_to_log_file(line)
					sys.stdout.write(line)
					sys.stdout.flush()
					u.prev_buf_was_output=True
				return

def check_for_user_process_creation(trace):
	if trace['syscall_nr']==56 or trace['syscall_nr']==57:
		uid = trace['uid']
		bash_pid = trace['pid']
		for u in TRACKED_USERS:
			if u.uid == uid and u.bash_pid==bash_pid:
				u.bash_clone_pid.append(trace['return_value'])
				return


def check_for_user_process_end(trace):
	if trace['syscall_nr']==61:
		uid = trace['uid']
		bash_pid = trace['pid']
		for u in TRACKED_USERS:
			if u.uid == uid and u.bash_pid==bash_pid:
				if trace['return_value'] in u.bash_clone_pid:
					u.bash_clone_pid.remove(trace['return_value'])
					return


def main_loop():
	while(not os.path.exists('LogFile.txt')):
		pass
	f=open('LogFile.txt','r')
	f.readline()
	while(1):
		line=f.readline()
		if line:
			try:
				trace = ast.literal_eval(line)
				check_for_new_sshed_users(trace)
				check_for_user_logout(trace)
				check_for_user_process_creation(trace)
				check_for_user_input(trace)
				check_for_user_process_end(trace)
			except SyntaxError:
				pass


def start_libvmtrace(pvm_id):
	global GLOBAL_SUB_PROCESS
	GLOBAL_SUB_PROCESS = subprocess.Popen('./libvmtrace2/apps/csec '+pvm_id+' > LogFile.txt', stdout=subprocess.PIPE, shell=True, preexec_fn=os.setsid) 


def stop_libvmtrace():
	os.killpg(os.getpgid(GLOBAL_SUB_PROCESS.pid), signal.SIGTERM)



def check_for_already_logged_users():
	run_vol_ps_aux()
	for u in TRACKED_USERS:
		run_vol_ps_tree(u)
		run_vol_ps_netstat(u)


def run_vol_ps_aux():
	try:
		sshds=(subprocess.check_output(["/usr/src/volatility/vol.py -f /mnt/mem --profile=LinuxDebian8x64 linux_psaux | grep 'sshd' | grep @"], stderr=subprocess.STDOUT, shell=True)).split('\n')[1:-1]
	except subprocess.CalledProcessError:
		sshds=[]
		return
	for trace_string in sshds:
		name = re.search(' (\w+)@',trace_string).group(1)
		sshd_pid = re.search('^(\d+) ',trace_string).group(1)
		uid = re.search('\s(\d+)\s',trace_string).group(1)
		user = SuspectedUser(int(uid), int(sshd_pid), name=name)
		TRACKED_USERS.append(user)


def run_vol_ps_tree(user):
	try:
		processes=(subprocess.check_output(["/usr/src/volatility/vol.py -f /mnt/mem --profile=LinuxDebian8x64 linux_pstree -p "+str(user.sshd_pid)], stderr=subprocess.STDOUT, shell=True)).split('\n')[2:-1]
	except subprocess.CalledProcessError:
		processes=[]
		return
	if 'bash' in processes[1]:
		bash_pid = re.search('\s(\d+)\s',processes[1]).group(1)
		user.bash_pid=int(bash_pid)


def run_vol_ps_netstat(user):
	try:
		networks=(subprocess.check_output(["/usr/src/volatility/vol.py -f /mnt/mem --profile=LinuxDebian8x64 linux_netstat | grep ESTABLISHED | grep "+str(user.sshd_pid)], stderr=subprocess.STDOUT, shell=True)).split('\n')[1:-1]
	except subprocess.CalledProcessError:
		networks=[]
		return
	p = re.sub("\s+"," ", networks[0])
	p = re.sub("\s:\s", ":", p)
	p = re.sub("\s:", ":", p)
	p = p.split(" ")[2]
	user.ip = p
	user.print_login()
	user.create_log_file()


try:
	pvm_id = sys.argv[1]
except IndexError as e:
	print("VM name input is missing")
	exit()
subprocess.call(['umount', '/mnt'], stderr=subprocess.STDOUT)
subprocess.call(['vmifs', 'name', pvm_id, '/mnt'], stderr=subprocess.STDOUT)

signal.signal(signal.SIGINT, exit_the_tool)

start_libvmtrace(pvm_id)
check_for_already_logged_users()
main_loop()


