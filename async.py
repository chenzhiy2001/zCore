import gdb
import os
import time
import threading
import subprocess
import ctypes
import ctypes.util
import sys
import re
import signal
import struct
import fcntl
import errno

project_root = "."
# command for logging at function entry
class FunctionEntryLogger(gdb.Command):
    def __init__(self):
        super().__init__("function_entry_logger", gdb.COMMAND_USER)
        self.func_name = "unknown"
        self.depth = -114514
    def invoke(self, arg, from_tty):
        # arg is the function name
        self.func_name = arg
        thread_id = gdb.selected_thread().ptid[1]
        timestamp = time.time()
        frame = gdb.newest_frame()
        self.location = frame.pc()
        self.depth = 0
        while frame is not None:
            self.depth += 1
            frame = frame.older()
        print(f"{timestamp:.6f}   {thread_id}: [entry] {self.func_name}({self.location}) depth: {self.depth}")

# command for logging at function exit
class FunctionExitLogger(gdb.Command):
    def __init__(self):
        super().__init__("function_exit_logger", gdb.COMMAND_USER)
        self.func_name = "unknown"
        self.depth = -114514
    def invoke(self, arg, from_tty):
        # arg is the function name
        self.func_name = arg
        thread_id = gdb.selected_thread().ptid[1]
        timestamp = time.time()
        frame = gdb.newest_frame()
        self.location = frame.pc()
        self.depth = 0
        while frame is not None:
            self.depth += 1
            frame = frame.older()
        print(f"{timestamp:.6f}   {thread_id}: [exit ] {self.func_name}({self.location}) depth: {self.depth}")

class FunctionReturnBreakpoint(gdb.FinishBreakpoint):
    def __init__(self, func_name):
        super().__init__()
        self.func_name = func_name
        self.depth = -114514
    def stop (self):
        self.log()
        return False
    def out_of_scope(self):
        self.log()
        return
    def log(self):
        thread_id = gdb.selected_thread().ptid[1]
        timestamp = time.time()
        frame = gdb.newest_frame()
        self.location = frame.pc()
        self.depth = 0
        while frame is not None:
            self.depth += 1
            frame = frame.older()
        print(f"{timestamp:.6f}   {thread_id}: [exit ] {self.func_name}({self.location}) depth: {self.depth}")

class RegisterFunctionReturnBreakpoint(gdb.Command):
    def __init__(self):
        super().__init__("register-function-return-breakpoint", gdb.COMMAND_USER)
        self.func_name = "unknown"
    def invoke(self, arg, from_tty):
        # arg is the function name
        self.func_name = arg
        print("bruh")
        FunctionReturnBreakpoint(self.func_name)


def get_addr_and_func_name(line:str)->tuple[str, str]:
    parts = line.split()
    if len(parts) >= 2:
        func_addr = "0x"+parts[0]
        func_name = line.strip(parts[0]+" "+parts[1]).strip()
        return func_addr, func_name
    print(f"Invalid line format: {line}")
    return None, None

def register_loggers(symbol_file_path):
    with open(symbol_file_path, "r") as f:
        for line in f:
            (func_addr, func_name) = get_addr_and_func_name(line)
            # gdb.execute(f"""
            #     break *{func_addr}
            #     command
            #     silent
            #     function_entry_logger {func_name}
            #     finish
            #     function_exit_logger {func_name}
            #     continue
            #     end
            # """)
            gdb.execute("break *"+func_addr+"\ncommands\nfunction_entry_logger "+func_name+"\nregister-function-return-breakpoint "+func_name+"\ncontinue\nend")
            # looks like you can't embed commands in commands, so using finish does not work
            # gdb.execute("break *"+func_addr+"\ncommands\nsilent\nfunction_entry_logger "+func_name+"\nfinish\nfunction_exit_logger "+func_name+"\ncontinue\nend")

FunctionEntryLogger()
FunctionExitLogger()
RegisterFunctionReturnBreakpoint();
register_loggers(project_root+"/rootfs/riscv64/zcore-async-fn.sym")