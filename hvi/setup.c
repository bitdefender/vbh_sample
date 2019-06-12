#include "hvi.h" /* Include this first for pr_fmt. */

#include <linux/module.h>
#include <asm/processor-flags.h>
#include <linux/sched.h>
#include <linux/kprobes.h>
#include <asm/uaccess.h>
#include <linux/slab.h>

#include "hypervisor_introspection.h"
#include "vmx_common.h"

#define STRINGIFY(x)                        #x
#define TOSTRING(x)                         STRINGIFY(x)
#define KVI_LOAD_INTROSPECTION_HYPERCALL    41


extern unsigned long long g_vdso_physical_address;
extern int enable_vdso_protection(void);
extern int disable_vdso_protection(void);
extern void asm_make_vmcall(unsigned int hypercall_id, void *params);

static int dfo_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs);
static int dfo_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs);
static int loader(void);
static int unloader(void);

static int hvi_loaded = 0;
static int should_unload = 0;

static struct kretprobe dfo_kretprobe = {
    .handler        = dfo_ret_handler,
    .entry_handler  = dfo_entry_handler,
    .kp.symbol_name = "do_filp_open",
};

struct open_flags_c {
    int open_flag;
    umode_t mode;
    int acc_mode;
    int intent;
    int lookup_flags;
};

static int dfo_entry_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct filename *filename = (struct filename *)regs->si;
    struct open_flags_c *op = (struct open_flags_c *)regs->dx;

    // we remove O_TRUNC flag for all files with
    // proc/self/fd in name
    if (strstr(filename->name, "/proc/self/fd"))
    {
        op->open_flag &= ~O_TRUNC;
        return 0;
    }

    return !0;
}

static int dfo_ret_handler(struct kretprobe_instance *ri, struct pt_regs *regs)
{
    struct file *retval = (struct file *)regs->ax;

    if (likely(!IS_ERR(retval)))
    {
        if (likely(NULL != retval->f_path.dentry->d_name.name))
        {
            // if the opened file is docker-runc
            // we make a vmcall with the opening flags
            if (unlikely(!strcmp(retval->f_path.dentry->d_name.name, "docker-runc")))
            {
                int flags = (u64)retval->f_flags;
                asm_make_vmcall(DFO_HYPERCALL, (void *)&flags);
                if (flags == -EACCES)
                {
                    pr_err("There was an attempt to overwrite docker-runc\n");
                    regs->ax = -EACCES;
                }
            }
        }
    }
    return 0;
}

int cr4_write_callback(hv_event_e type, unsigned char* data, int size, int *allow)
{
    struct hvi_event_cr *cr_event;

    *allow = 1;         // Allow the action if an error occurs

    if (type != cr_write)
    {
        pr_err("Invalid event type sent to cr4_write_callback: %d\n", type);
        return 0;       // vbh doesn't check the error code so its fine
    }

    if (size < sizeof(struct hvi_event_cr))
    {
        pr_err("Invalid data size.\n");
        return 0;
    }

    cr_event = (struct hvi_event_cr*)data;
    if (cr_event->cr != CPU_REG_CR4)
    {
        pr_err("Invalid CR register. Expected CR4, got CR%d\n", cr_event->cr);
        return 0;
    }

    if (((X86_CR4_SMAP & cr_event->old_value) && !(X86_CR4_SMAP & cr_event->new_value)) ||
        ((X86_CR4_SMEP & cr_event->old_value) && !(X86_CR4_SMEP & cr_event->new_value)))
    {
        *allow = 0;
        // useless log, kernel is likely going to crash immediately after this :(
        pr_warn("Malicious activity detected. Process %s tried to disable SMAP/SMEP. Will deny!\n", current->comm);
    }

    return 0;
}


int handle_vmcall(hv_event_e type, unsigned char* data, int size, int *allow)
{
    if (type != vmcall)
    {
        pr_err("Invalid event type sent to vmcall handler: %d\n", type);
        return 0;
    }

    if (!hvi_loaded)
    {
        pr_info("Entered vmx-root. Will initialize the rest of hvi.\n");
        return loader();
    }

    // for CVE-2019-5736
    if (NULL != data)
    {
        // deny access if the write flag is set
        int *params = (int *)data;
        if ((*params & O_WRONLY))
        {
            *params = -EACCES;
        }
        return 0;
    }

    if (should_unload)
    {
        pr_info("Entered vmx-root. Uninitializing...\n");
        return unloader();
    }

    pr_err("Unhandled vmcall!\n");
    return 0;
}


int handle_ept_violation(hv_event_e type, unsigned char* data, int size, int *allow)
{
    struct hvi_event_ept_violation *ept_violation_event;
    if (type != ept_violation)
    {
        pr_err("Invalid event type sent to ept_violation handler: %d\n", type);
        return 0;
    }

    if (size < sizeof(struct hvi_event_ept_violation))
    {
        pr_err("Invalid data size.\n");
        return 0;
    }

    ept_violation_event = (struct hvi_event_ept_violation*)data;

    pr_info("ept violation. GPA = 0x%llx  GLA = 0x%llx.\n", ept_violation_event->gla, ept_violation_event->gpa);
    if (ept_violation_event->gpa >= g_vdso_physical_address && ept_violation_event->gpa < g_vdso_physical_address + 2 * PAGE_SIZE)
    {
        pr_warn("Malicious write into vdso. Will deny!\n");
        *allow = 0;
    }
    else
    {
        pr_warn("Unhandled ept violation. Will allow!\n");
        *allow = 1;
    }

    return 0;
}


int register_cr4_write_callback(void)
{
    struct hvi_event_callback cr4_event_callback;
    int status;

    cr4_event_callback.event = cr_write;
    cr4_event_callback.callback = cr4_write_callback;

    status = hvi_register_event_callback(&cr4_event_callback, 1);
    if (status)
    {
        pr_err("hvi_register_event_callback failed for cr4_write_callback. Error: %d\n", status);
    }

    return status;
}


int register_vmcall_callback(void)
{
    struct hvi_event_callback vmcall_event_callback;
    int status;

    vmcall_event_callback.event = vmcall;
    vmcall_event_callback.callback = handle_vmcall;

    status = hvi_register_event_callback(&vmcall_event_callback, 1);
    if (status)
    {
        pr_err("hvi_register_event_callback failed for vmcall_event. Error: %d\n", status);
    }

    return status;
}


int register_ept_violation_callback(void)
{
    struct hvi_event_callback ept_violation_event_callback;
    int status;

    ept_violation_event_callback.event = ept_violation;
    ept_violation_event_callback.callback = handle_ept_violation;

    status = hvi_register_event_callback(&ept_violation_event_callback, 1);
    if (status)
    {
        pr_err("hvi_register_event_callback failed for ept_violation_callback. Error: %d\n", status);
    }

    return status;
}


int enable_cr4_exits(void)
{
    hvi_modify_cr_write_exit(CPU_REG_CR4, ~(unsigned int)0, 1);

    return 0;
}


int disable_cr4_exits(void)
{
    hvi_modify_cr_write_exit(CPU_REG_CR4, ~(unsigned int)0, 0);

    return 0;
}

int register_do_filp_open_kretprobe(void)
{
    int status;

    // register a kprobe on do_filp_open so we could
    // filter file access
    status = register_kretprobe(&dfo_kretprobe);
    if (status < 0)
    {
        pr_err("register_kretprobe failed, returned %d\n", status);
        return status;
    }
    return 0;
}

int loader(void)
{
    int status = 0;

    status = register_cr4_write_callback();
    if (status)
    {
        return status;
    }

    status = register_ept_violation_callback();
    if (status)
    {
        goto _done_unregister_cr4_callback;
    }

    if (hvi_request_vcpu_pause(0))
    {
        goto _done_unregister_ept_violation_callback;
    }

    status = enable_cr4_exits();
    if (status)
    {
        goto _done_resume_vcpus;
    }

    enable_vdso_protection();

    hvi_loaded = 1;

    pr_info("Hvi successfully initialized!\n");

    status = 0;

_done_resume_vcpus:
    if (hvi_request_vcpu_resume())
    {
        pr_err("Could not resume vcpus!\n");
    }

    if (0 == status)
    {
        return status;
    }

_done_unregister_ept_violation_callback:
    hvi_unregister_event_callback(ept_violation);

_done_unregister_cr4_callback:
    hvi_unregister_event_callback(cr_write);

    return status;
}


int unloader(void)
{
    hvi_request_vcpu_pause(0);

    disable_cr4_exits();
    disable_vdso_protection(); // We do this here because EPT paging structures are not available in vmx non-root.

    hvi_request_vcpu_resume();

    return 0;
}


static int __init hvi_init(void)
{
    // little big hack ingoming
    // register the VMCALL handler, then issue a vmcall to enter vmx root

    pr_info("Will register VMCALL callback.\n");

    if (register_vmcall_callback())
    {
        pr_err("Failed to register vmcall handler. Will abort initialization.\n");
        return 0;
    }

    pr_info("VMCALL callback registered. Will now try to enter vmx-root.\n");

    asm_make_vmcall(KVI_LOAD_INTROSPECTION_HYPERCALL, NULL);

    if (register_do_filp_open_kretprobe())
    {
        pr_err("Failed to register dfo kretprobe.\n");
    }

    pr_info("kretprobe registered.\n");
    return 0;
}


static void __exit hvi_uninit(void)
{
    pr_info("Uninitializing Hvi...\n");

    should_unload = 1;
    asm_make_vmcall(KVI_LOAD_INTROSPECTION_HYPERCALL, NULL);

    unregister_kretprobe(&dfo_kretprobe);
    hvi_unregister_event_callback(vmcall);
    hvi_unregister_event_callback(cr_write);
    hvi_unregister_event_callback(ept_violation);

    pr_info("Hvi successfully uninitialized!\n");
}


module_init(hvi_init);
module_exit(hvi_uninit);
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
MODULE_AUTHOR("Bogdan-Viorel BOSINTA <bbosinta@bitdefender.com>, "
              "Alexandru-Ciprian Cihodaru <acihodaru@bitdefender.com>");
