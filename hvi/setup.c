#include <linux/module.h>
#include <linux/printk.h>
#include <asm/processor-flags.h>
#include <linux/sched.h>

#include "hypervisor_introspection.h"

#define CR4                                 4

#define STRINGIFY(x)                        #x
#define TOSTRING(x)                         STRINGIFY(x)
#define KVI_LOAD_INTROSPECTION_HYPERCALL    41


extern unsigned long long g_vdso_physical_address;
int enable_vdso_protection(void);
int disable_vdso_protection(void);

int hvi_loaded = 0;
int should_unload = 0;

int loader(void);
int unloader(void);

int cr4_write_callback(hv_event_e type, unsigned char* data, int size, int *allow)
{
    struct hvi_event_cr *cr_event;

    *allow = 1;         // Allow the action if an error occurs

    if (type != cr_write)
    {
        printk(KERN_ERR "[ERROR] Invalid event type sent to cr4_write_callback: %d\n", type);
        return 0;       // vbh doesn't check the error code so its fine
    }

    if (size < sizeof(struct hvi_event_cr))
    {
        printk(KERN_ERR "[ERROR] Invalid data size.\n");
        return 0;
    }

    cr_event = (struct hvi_event_cr*)data;
    if (cr_event->cr != CR4)
    {
        printk(KERN_ERR "[ERROR] Invalid CR register. Expected CR4, got CR%d\n", cr_event->cr);
        return 0;
    }

    if (((X86_CR4_SMAP & cr_event->old_value) && !(X86_CR4_SMAP & cr_event->new_value)) ||
        ((X86_CR4_SMEP & cr_event->old_value) && !(X86_CR4_SMEP & cr_event->new_value)))
    {
        *allow = 0;
        // useless log, kernel is likely going to crash immediately after this :(
        printk(KERN_ERR "[WARNING] Malicious activity detected. Process %s tried to disable SMAP/SMEP. Will deny!\n", current->comm);
    }

    return 0;
}


int handle_vmcall(hv_event_e type, unsigned char* data, int size, int *allow)
{
    if (type != vmcall)
    {
        printk(KERN_ERR "[ERROR] Invalid event type sent to vmcall handler: %d\n", type);
        return 0;
    }

    if (!hvi_loaded)
    {
        printk(KERN_ERR "[INFO] Entered vmx-root. Will initialize the rest of hvi.\n");
        return loader();
    }
    if (should_unload)
    {
        printk(KERN_ERR "[INFO] Entered vmx-root. Uninitializing...\n");
        return unloader();
    }

    printk(KERN_ERR "[WARNING] Unhandled vmcall!\n");
    return 0;
}


int handle_ept_violation(hv_event_e type, unsigned char* data, int size, int *allow)
{
    struct hvi_event_ept_violation *ept_violation_event;
    if (type != ept_violation)
    {
        printk(KERN_ERR "[ERROR] Invalid event type sent to ept_violation handler: %d\n", type);
        return 0;
    }

    if (size < sizeof(struct hvi_event_ept_violation))
    {
        printk(KERN_ERR "[ERROR] Invalid data size.\n");
        return 0;
    }

    ept_violation_event = (struct hvi_event_ept_violation*)data;

    printk(KERN_ERR "ept violation. GPA = 0x%llx  GLA = 0x%llx.\n", ept_violation_event->gla, ept_violation_event->gpa);
    if (ept_violation_event->gpa >= g_vdso_physical_address && ept_violation_event->gpa < g_vdso_physical_address + 2 * PAGE_SIZE)
    {
        printk(KERN_ERR "[WARNING] Malicious write into vdso. Will deny!\n");
        *allow = 0;
    }
    else
    {
        printk(KERN_ERR "[INFO] Unhandled ept violation. Will allow!\n");
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
        printk(KERN_ERR "[ERROR] hvi_register_event_callback failed for cr4_write_callback. Error: %d\n", status);
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
        printk(KERN_ERR "[ERROR] hvi_register_event_callback failed for vmcall_event. Error: %d\n", status);
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
        printk(KERN_ERR "[ERROR] hvi_register_event_callback failed for ept_violation_callback. Error: %d\n", status);
    }

    return status;
}


int enable_cr4_exits(void)
{
    hvi_modify_cr_write_exit(CR4, ~(unsigned int)0, 1);

    return 0;
}


int disable_cr4_exits(void)
{
    hvi_modify_cr_write_exit(CR4, ~(unsigned int)0, 0);

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

    printk(KERN_ERR "[INFO] Hvi successfully initialized!\n");

    status = 0;

_done_resume_vcpus:
    if (hvi_request_vcpu_resume())
    {
        printk(KERN_ERR "Could not resume vcpus!\n");
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

    printk(KERN_ERR "[INFO] Will register VMCALL callback.\n");

    if (register_vmcall_callback())
    {
        printk(KERN_ERR "[ERORR] Failed to register vmcall handler. Will abort initialization.\n");
        return 0;
    }

    printk(KERN_ERR "[INFO] VMCALL callback registered. Will now try to enter vmx-root.\n");

    asm volatile("mov $" TOSTRING(KVI_LOAD_INTROSPECTION_HYPERCALL) ", %rax;"
                 "vmcall;");
    return 0;
}


static void __exit hvi_uninit(void)
{
    printk(KERN_ERR "[INFO] Uninitializing Hvi...\n");

    should_unload = 1;
    asm volatile("mov $" TOSTRING(KVI_LOAD_INTROSPECTION_HYPERCALL) ", %rax;"
                 "vmcall;");

    hvi_unregister_event_callback(vmcall);
    hvi_unregister_event_callback(cr_write);
    hvi_unregister_event_callback(ept_violation);

    printk(KERN_ERR "[INFO] Hvi successfully uninitialized!\n");
}


module_init(hvi_init);
module_exit(hvi_uninit);
MODULE_LICENSE("GPL");
MODULE_VERSION("0.1");
MODULE_AUTHOR("Bogdan-Viorel BOSINTA <bbosinta@bitdefender.com>");
