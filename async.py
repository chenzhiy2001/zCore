# a gdb python script to probe async functions
# this script will be used to probe async functions in the zcore kernel

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

# a function to break on function and its return.
# it works like this: it set a breakpoint at the function you want to probe. when this breakpoint is hit (which means the function is called), it will print time, thread id, function name, function address, depth and entry/exit. then it will save the return address, replace it with a trampoline and set a breakpoint at the trampoline. when the trampoline breakpoint is hit (which means the function exited), it will print time, thread id, function name, function address, depth and entry/exit. then it will restore the return address and remove the trampoline breakpoint.

class AsyncFunctionProbe(gdb.Command):
    """Probe async functions by setting breakpoints on entry and exit."""

    def __init__(self):
        super(AsyncFunctionProbe, self).__init__("probe-async", gdb.COMMAND_USER)

    def invoke(self, arg, from_tty):
        args = gdb.string_to_argv(arg)
        if len(args) != 1:
            gdb.write("Usage: probe-async <function_name>\n", gdb.STDERR)
            return

        function_name = args[0]
        self.set_entry_breakpoint(function_name)

    def set_entry_breakpoint(self, function_name):
        entry_bp = gdb.Breakpoint(function_name)
        entry_bp.silent = True
        entry_bp.stop = self.on_entry

    def on_entry(self, bp):
        frame = gdb.newest_frame()
        function_name = frame.name()
        thread_id = gdb.selected_thread().ptid[1]
        function_address = frame.pc()
        timestamp = time.time()

        gdb.write(f"[ENTRY] Time: {timestamp}, Thread ID: {thread_id}, "
                  f"Function: {function_name}, Address: {function_address}\n")

        return_address = frame.older().pc()
        trampoline_bp = gdb.Breakpoint("*" + hex(return_address))
        trampoline_bp.silent = True
        trampoline_bp.stop = self.on_exit
        trampoline_bp.function_name = function_name
        trampoline_bp.thread_id = thread_id
        trampoline_bp.timestamp = timestamp

        return False

    def on_exit(self, bp):
        timestamp = time.time()
        gdb.write(f"[EXIT] Time: {timestamp}, Thread ID: {bp.thread_id}, "
                  f"Function: {bp.function_name}, Address: {bp.location}\n")
        bp.delete()
        return False


AsyncFunctionProbe()