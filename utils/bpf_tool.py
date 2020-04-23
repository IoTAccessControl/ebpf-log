# coding: utf-8

def load_bpf_text(filename, params):
    text = ""
    with open(filename, "r") as fp:
        text = fp.read()
    for key, val in params.items():
        text = text.replace(f"#define {key} 0", f"#define {key} {val}") 
        print(f"#define {key} 0", f"#define {key} {val}")
    return text

# print(load_bpf_text("ebpf/tcp_filter.c", {"SRC_IP": 2}))