# coding: utf-8
import logging
import threading

def setup():
    # logging.basicConfig(filename='run.log',level=logging.DEBUG)
    logging.basicConfig(level=logging.DEBUG)

def run_tcp_filter(threads):
    from tcp.filter import main as tcp_main
    th = threading.Thread(target=tcp_main, daemon=True)
    logging.info("Starting tcp_filter")
    th.start()
    threads.append(th)
    

def main():
    setup()
    threads = []
    run_tcp_filter(threads)

    for thd in threads:
        thd.join()
    logging.info("Exit")

if __name__ == "__main__":
    main()
