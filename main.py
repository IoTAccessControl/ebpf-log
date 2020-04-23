# coding: utf-8
import logging
import threading

def setup():
    # logging.basicConfig(filename='run.log',level=logging.DEBUG)
    logging.basicConfig(level=logging.DEBUG)

def run_http_filter(threads):
    from http.filter import main as http_main
    th = threading.Thread(target=http_main, daemon=True)
    logging.info("Starting http_filter")
    th.start()
    threads.append(th)
    

def main():
    setup()
    threads = []
    run_http_filter(threads)

    for thd in threads:
        thd.join()
    logging.info("Exit")

if __name__ == "__main__":
    main()
