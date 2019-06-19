/* SPDX-License-Identifier: GPL-2.0 */

#ifndef _HVI_H
#define _HVI_H

/*
 * XXX: Make sure this header is included before others, so our `pr_fmt' is
 * used.
 */
#ifndef pr_fmt
#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt
#endif /* pr_fmt */

extern unsigned long long g_vdso_physical_address;
extern int enable_vdso_protection(void);
extern int disable_vdso_protection(void);
extern void asm_make_vmcall(unsigned int hypercall_id, void *params);

#endif /* _HVI_H */
