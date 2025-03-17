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
import argparse
import paramiko
import datetime

from openai import OpenAI
client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-3.5-turbo")
DEFAULT_USER = os.getenv("DEFAULT_USER", "admin")
DEFAULT_HOSTNAME = os.getenv("DEFAULT_HOSTNAME", "virtual-machine")
USER_PASSWORD = os.getenv("USER_PASSWORD", "password")
LOG_FILE = os.getenv("LOG_FILE", "tropico-ssh.log")

# Setup logging
# logging.basicConfig()
# paramiko.util.log_to_file(LOG_FILE, level='INFO')
# logger = paramiko.util.get_logger("paramiko")

def log_ssh_event(event_type, ip, details=''):
    with open(LOG_FILE, 'a') as log:
        log.write(f"{datetime.datetime.now(datetime.UTC).isoformat()} | IP: {ip} | Event: {event_type}\n")
        log.write(f"{details}\n")
        log.write("-" * 60 + "\n")

host_key = paramiko.RSAKey(filename='./rsa')

SUPPORT_EXIT = True
in_q = Queue()

class Server(paramiko.ServerInterface):
    def __init__(self, mode, client_ip):
        self.client_ip = client_ip
        self.event = threading.Event()
        self.master_fd = None
        self.mode = mode

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED
        return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED

    def check_auth_password(self, username, password):
        log_ssh_event("Authentication Attempt", self.client_ip, f"Username: {username}, Password: {password}")
        if username == DEFAULT_USER and password == USER_PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return 'publickey,password'

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        ip = channel.getpeername()[0]
        log_ssh_event(f"PTY request: {width}x{height}", ip)
        self.pty_width = width
        self.pty_height = height
        return True

    def check_channel_window_change_request(self, channel, width, height, pixelwidth, pixelheight):
        ip = channel.getpeername()[0]
        log_ssh_event(f"Window size change: {width}x{height}", ip)
        if self.master_fd:
            winsize = struct.pack('HHHH', height, width, 0, 0)
            fcntl.ioctl(self.master_fd, termios.TIOCSWINSZ, winsize)
        return True

    def check_channel_shell_request(self, channel):
        if self.mode == 'real':
            master_fd, slave_fd = os.openpty()
            self.master_fd = master_fd
            threading.Thread(target=run_real_shell, args=(channel, self.event, master_fd, slave_fd), daemon=True).start()
        elif self.mode == 'llm':
            threading.Thread(target=run_llm_shell, args=(channel, self.event), daemon=True).start()
        return True

    def check_channel_exec_request(self, channel, command):
        command = command.decode()
        ip = channel.getpeername()[0]
        log_ssh_event(f"Exec Command: {command}", ip)
        if self.mode == 'real':
            try:
                result = subprocess.run(command, shell=True, capture_output=True, text=True)
                channel.send(result.stdout)
                if result.stderr:
                    channel.send(result.stderr)
            except Exception as e:
                channel.send(f"Error executing command: {e}\n")
        elif self.mode == 'llm':
            response = get_llm_response(command)
            channel.send(response + '\n')
        self.event.set()
        return True


def run_real_shell(channel, event, master_fd, slave_fd):
    ip = channel.getpeername()[0]
    shell = subprocess.Popen(
        ['/bin/bash', '-l'],
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        preexec_fn=os.setsid,
        cwd="/home/admin",
        env={"HOME": "/home/admin", "USER": "admin"}
    )
    os.close(slave_fd)
    # Flush initial output
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
            break

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

def run_llm_shell(channel, event):
    ip = channel.getpeername()[0]
    prompt = f"{DEFAULT_USER}@{DEFAULT_HOSTNAME}:~$ "
    channel.send(prompt)

    # Initialize per-session message history
    message_history = [
        {
            "role": "system",
            "content": f"You will act as an Ubuntu Linux terminal. The user will type commands, and you are to reply with what the terminal should show. Your responses must be contained within a single code block. Do not provide notes. Do not provide explanations or type commands unless explicitly instructed by the user. Your entire response/output is going to consist of a simple text with \n for new line, and you will NOT wrap it within string md markers. The default user should be {DEFAULT_USER} belonging to group {DEFAULT_USER}. The machine hostname is {DEFAULT_HOSTNAME}."
        }
    ]

    buffer = ''
    while True:
        data = channel.recv(1024)
        if not data:
            break
        i = 0
        while i < len(data):
            char = chr(data[i])

            # Handle arrow keys (escape sequences)
            if char == '\x1b':  # ESC
                if i + 2 < len(data):
                    seq = data[i:i+3].decode()
                    if seq in ['\x1b[A', '\x1b[B', '\x1b[C', '\x1b[D']:
                        i += 3  # Skip escape sequence
                        continue
                i += 1
                continue

            # Handle backspace
            if char == '\x7f':
                if buffer:
                    buffer = buffer[:-1]
                    channel.send('\b \b')
                i += 1
                continue

            # Handle Ctrl+D (EOF)
            if char == '\x04':
                channel.send('\r\nlogout\r\n')
                log_ssh_event("Logout Executed", ip)
                event.set()
                return

            # Handle Ctrl+C
            if char == '\x03':
                buffer = ''
                channel.send('^C\r\n')
                log_ssh_event("Ctrl-C Executed (prompt)", ip)
                channel.send(prompt)
                i += 1
                continue

            # Echo input normally
            channel.send(char)

            # Handle Enter
            if char in ('\n', '\r'):
                channel.send('\r\n')
                command = buffer.strip()
                log_ssh_event("Command Executed", ip, f"Command: {command}")
                if command in ('exit', 'quit'):
                    event.set()
                    return
                if command:
                    message_history.append({"role": "user", "content": command})
                    response = get_llm_response(message_history).rstrip()
                    message_history.append({"role": "assistant", "content": response})
                    for line in response.splitlines():
                        channel.send(line + '\r\n')
                buffer = ''
                channel.send(prompt)
            else:
                buffer += char
            i += 1

def get_llm_response(message_history):
    response = client.chat.completions.create(
        model=OPENAI_MODEL,
        messages=message_history
    )
    return response.choices[0].message.content

def run_server(client, mode, addr):
    t = paramiko.Transport(client)
    t.set_gss_host(socket.getfqdn(""))
    t.load_server_moduli()
    t.add_server_key(host_key)
    server = Server(mode, addr[0])
    t.start_server(server=server)
    server.event.wait()
    t.close()


def accept(sock, mode):
    while True:
        try:
            client, addr = sock.accept()
            log_ssh_event("New Connection", addr[0], "SSH connection accepted")
        except Exception as exc:
            log_ssh_event("Error", exc, '')
        else:
            in_q.put((client, mode, addr))


def listener(mode):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(('', 22))
    sock.listen(100)
    print('Listening on port 22')

    threading.Thread(target=accept, args=(sock, mode), daemon=True).start()

    while True:
        try:
            client, mode, addr = in_q.get()
            if SUPPORT_EXIT and client is None:
                break
            threading.Thread(target=run_server, args=(client, mode, addr), daemon=True).start()
        except KeyboardInterrupt:
            sys.exit(0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--mode', choices=['real', 'llm'], default='real', help='Execution mode: real or llm')
    args = parser.parse_args()
    listener(args.mode)
