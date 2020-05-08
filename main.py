# coding: utf-8
import sys
import logging
import threading

threads = []

def setup():
	# logging.basicConfig(filename='run.log',level=logging.DEBUG)
	logging.basicConfig(level=logging.DEBUG)
	if sys.version_info < (3, 6):
		logging.error("Require python version >= 3.6.")
		exit(-1)

def run_tcp_log_monitor():
	from tcp.filter import main as tcp_main
	th = threading.Thread(target=tcp_main, daemon=True)
	logging.info("Starting tcp_filter.")
	th.start()
	threads.append(th)

def run_xdp_policy():
	from tcp.xdp_policy import main as policy_main
	th = threading.Thread(target=policy_main, daemon=True)
	logging.info("Starting xdp policy manager.")
	th.start()
	threads.append(th)

def wait_to_exit():
	for thd in threads:
		thd.join()

def main():
	setup()
	# run_tcp_log_monitor()
	run_xdp_policy()
	wait_to_exit()
	logging.info("Exit.")

def cleanup():
	import tcp.xdp_policy as xdp_policy
	xdp_policy.release()

if __name__ == "__main__":
	main()
	try:
		pass
	except KeyboardInterrupt:
		logging.info("Exit by ctrl-c.")
	finally:
		exit(0)
