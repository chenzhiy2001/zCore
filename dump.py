import subprocess
import json

def process_log_file(file_path):
    result_text = []
    with open(file_path, 'r') as file:
        for line in file:
            if "time-threadID-entry/exit-addr-depth:" in line:
                async_line = line.split("time-threadID-entry/exit-addr-depth:")[1].strip()
                parts = async_line.split(" ")
                # Remove null characters from the parts
                parts = [part.replace("\x00", "") for part in parts]
                # print(parts)
                time = int(parts[0])
                thread_id = int(parts[1])
                entry_exit = parts[2]
                addr = hex(int(parts[3]))
                depth = int(parts[4])



                with open("rootfs/riscv64/zcore-async-fn.sym", "r") as sym_file:
                    addr = addr[2:] # remove 0x
                    # print(f"Searching for {addr} in zcore-async-fn.sym")
                    fn_name = "unknown"
                    
                    for sym_line in sym_file:
                        sym_parts = sym_line.split(" ")
                        if len(sym_parts) >= 2 and sym_parts[0] == addr:
                            fn_name = " ".join(sym_parts[2:]).splitlines()[0]
                            break

                if fn_name == "unknown":
                        addr2line_cmd = f"addr2line -e target/riscv64/release/zcore -f {addr} -C"
                        result = subprocess.run(addr2line_cmd, shell=True, capture_output=True, text=True)
                        fn_name = result.stdout.splitlines()[0]


                
                # if entry_exit == "exit":
                #     entry_exit = "exit "
                # // bpf_trace_printk("{} 1: [exit ] FUNCTION_NAME(FUNCTION_ADDR?PC={}) depth: {}\n",time,ctx->paddr,depth);
                print(f"{time}   {thread_id}: [{entry_exit}] {fn_name}({addr}) depth: {depth}")
                # append an object
                result_text.append({
                    "time": time,
                    "thread_id": thread_id,
                    "entry_exit": entry_exit,
                    "fn_name": fn_name,
                    "addr": addr,
                    "depth": depth
                })
    return result_text
                

if __name__ == "__main__":
    # https://unix.stackexchange.com/questions/694671/leave-color-in-stdout-but-remove-from-tee
    # cargo qemu --arch=riscv64 | tee >(sed $'s/\033[[][^A-Za-z]*[A-Za-z]//g' > async.log)
    result_text = process_log_file("async.log")
    trace_events = []
    for entry in result_text:
        ts = entry["time"]
        ph = "B" if entry["entry_exit"] == "entry" else "E"
        pid = str(entry["thread_id"])
        tid = f" {entry['thread_id']}"
        name = entry["fn_name"]
        args = {"Function address (For recognizing anonymous type)": f"0x{entry['addr']}"}

        trace_event = {
            "ts": ts,
            "ph": ph,
            "pid": pid,
            "tid": tid,
            "name": name,
        }

        if ph == "E":
            trace_event["args"] = args

        trace_events.append(trace_event)

    output = {
        "traceEvents": trace_events,
        "displayTimeUnit": "ms"
    }

    with open("output.json", "w") as json_file:
        json.dump(output, json_file, indent=4)