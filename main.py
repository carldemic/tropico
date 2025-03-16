#!/usr/bin/env python
import logging
import socket
import sys
import threading
from queue import Queue
import os
import subprocess
import select
import fcntl
import struct
import termios
import paramiko

# Logging setup
logging.basicConfig()
paramiko.util.log_to_file('demo_server.log', level='INFO')
logger = paramiko.util.get_logger("paramiko")

host_key = paramiko.RSAKey(filename='./rsa')

SUPPORT_EXIT = True

# Queue to accept incoming clients
in_q = Queue()


### === Server Class ===
class Server(paramiko.ServerInterface):
    def __init__(self):
        self.event = threading.Event()
        self.master_fd = None  # Store PTY master fd for window resizing

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        if password == '9999':
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'publickey,password'

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        logger.info(f"PTY request: {width}x{height}")
        self.pty_width = width
        self.pty_height = height
        return True

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        logger.info(f"Window size change: {width}x{height}")
        if self.master_fd:
            winsize = struct.pack('HHHH', height, width, 0, 0)
            fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, winsize)
        return True

    def check_channel_shell_request(self, channel):
        master_fd, slave_fd = os.openpty()
        self.master_fd = master_fd

        threading.Thread(target=my_processor, args=(channel, self.event, master_fd, slave_fd), daemon=True).start()
        return True

    def check_channel_exec_request(self, channel, command):
        command = command.decode()
        logger.info('Exec Command = %s', command)
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            channel.send(result.stdout)
            if result.stderr:
                channel.send(result.stderr)
        except Exception as e:
            channel.send(f"Error executing command: {e}\n")
        self.event.set()
        return True


### === Processor Function ===
def my_processor(channel, event, master_fd, slave_fd):
    # Start bash shell
    shell = subprocess.Popen(
        ['/bin/bash', '-l'],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        preexec_fn=os.setsid,
        cwd="/home/admin",  # Start in user's home directory
        env={"HOME": "/home/admin", "USER": "admin"}
    )

    os.close(slave_fd)

    # Immediately flush initial prompt/output
    while True:
        rlist, _, _ = select.select([master_fd], [], [], 0.05)
        if master_fd in rlist:
            try:
                data = os.read(master_fd, 1024)
                if not data:
                    break
                channel.send(data)
            except OSError:
                break
        else:
            break  # No more initial output to flush

    # Main loop: relay input/output
    try:
        while True:
            rlist, _, _ = select.select([channel, master_fd], [], [])

            if channel in rlist:
                data = channel.recv(1024)
                if not data:
                    break
                os.write(master_fd, data)

            if master_fd in rlist:
                try:
                    data = os.read(master_fd, 1024)
                    if not data:
                        break
                    channel.send(data)
                except OSError:
                    break
    finally:
        shell.terminate()
        event.set()


### === Server Connection ===
def run_server(client):
    t = paramiko.Transport(client)
    t.set_gss_host(socket.getfqdn(""))
    t.load_server_moduli()
    t.add_server_key(host_key)
    server = Server()
    t.start_server(server=server)
    server.event.wait()
    t.close()


def accept(sock):
    while True:
        try:
            client, _ = sock.accept()
        except Exception as exc:
            logger.error(exc)
        else:
            in_q.put(client)


### === Listener ===
def listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 22))

    sock.listen(100)
    print('SSH server listening')

    threading.Thread(target=accept, args=(sock,), daemon=True).start()

    while True:
        try:
            client = in_q.get()
            if SUPPORT_EXIT and client is None:
                break
            threading.Thread(target=run_server, args=(client,), daemon=True).start()
        except KeyboardInterrupt:
            sys.exit(0)


if __name__ == '__main__':
    listener()
