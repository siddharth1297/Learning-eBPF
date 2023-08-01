"""
Simple program
Run:
    Run this program.
    In another terminal run simple_execve.sh.
Result:
    The output(pid) of simple_execve.sh will appear in the trace section.

"""
from bcc import BPF

program = r"""
int hello(void *ctx) {
    bpf_trace_printk("Hello World!");
    return 0;
}
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
print(syscall)
b.attach_kprobe(event=syscall, fn_name="hello")

print("----------------Traces-------------------")
b.trace_print()
