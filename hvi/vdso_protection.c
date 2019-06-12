#include "hvi.h" /* Include this first for pr_fmt. */

#include <linux/string.h>
#include <linux/kallsyms.h>
#include "hypervisor_introspection.h"

#define LINUX_KERNEL_START kallsyms_lookup_name("_stext")

#ifndef PD_P
#define PD_P	0x001
#define PDP_PS	0x080
#endif

#define STATUS_SUCCESS				0
#define STATUS_UNSUCCESSFUL			-1
#define STATUS_NO_MORE_MAPPING_STRUCTURES	-2
#define STATUS_INVALID_INTERNAL_STATE		-4

#ifndef PAGE_SIZE_4K
#define PAGE_SIZE_4K (4 * 1024)
#define PAGE_SIZE_2M (2 * 1024 * 1024)
#define PAGE_SIZE_1G (1 * 1024 * 1024 * 1024)
#endif

#ifndef PAGE_SIZE
#define PAGE_SIZE PAGE_SIZE_4K
#endif

#ifndef PML4_INDEX
#define PML4_INDEX(a)	(unsigned int)(((a) & 0x0000ff8000000000) >> 39)
#define PDP_INDEX(a)	(unsigned int)(((a) & 0x0000007fc0000000) >> 30)
#define PD_INDEX(a)	(unsigned int)(((a) & 0x000000003fe00000) >> 21)
#define PT_INDEX(a)	(unsigned int)(((a) & 0x00000000001ff000) >> 12)
#endif

#ifndef CLEAN_PHYS_ADDRESS64
#define CLEAN_PHYS_ADDRESS64(x)	((x) & 0x000FFFFFFFFFF000)
#endif

unsigned long long g_vdso_physical_address;

struct va_translation {
	unsigned long long virtual_address;
	unsigned long long physical_address;
	unsigned long long page_size;
};

static int hvi_translate_va(unsigned long long va, unsigned long long cr3, struct va_translation *translation)
{
	int status;

	unsigned int pml4i, pdpi, pdi, pti;
	unsigned long long *pml4, *pdp, *pd, *pt;

	pml4 = pdp = pd = pt = NULL;

	translation->virtual_address = va;

	pml4i = PML4_INDEX(va);
	pdpi  = PDP_INDEX (va);
	pdi   = PD_INDEX  (va);
	pti   = PT_INDEX  (va);

	status = hvi_physmem_map_to_host(CLEAN_PHYS_ADDRESS64(cr3), PAGE_SIZE, 0, (void**)&pml4);
	if (status)
		goto cleanup_and_leave;

	if (!(pml4[pml4i] & PD_P)) {
		status = STATUS_NO_MORE_MAPPING_STRUCTURES;
		goto cleanup_and_leave;
	}

	status = hvi_physmem_map_to_host(CLEAN_PHYS_ADDRESS64(pml4[pml4i]), PAGE_SIZE, 0, (void**)&pdp);
	if (status)
		goto cleanup_and_leave;

	if (!(pdp[pdpi] & PD_P)) {
		status = STATUS_NO_MORE_MAPPING_STRUCTURES;
		goto cleanup_and_leave;
	}

	if (pdp[pdpi] & PDP_PS) {
		translation->page_size = PAGE_SIZE_1G;
		translation->physical_address = CLEAN_PHYS_ADDRESS64(pdp[pdpi]);
		status = STATUS_SUCCESS;
		goto cleanup_and_leave;
	}

	status = hvi_physmem_map_to_host(CLEAN_PHYS_ADDRESS64(pdp[pdpi]), PAGE_SIZE, 0, (void**)&pd);
	if (status)
		goto cleanup_and_leave;

	if (!(pd[pdi] & PD_P)) {
		status = STATUS_NO_MORE_MAPPING_STRUCTURES;
		goto cleanup_and_leave;
	}

	if (pd[pdi] & PDP_PS) {
		translation->page_size = PAGE_SIZE_2M;
		translation->physical_address = CLEAN_PHYS_ADDRESS64(pd[pdi]);
		status = STATUS_SUCCESS;
		goto cleanup_and_leave;
	}

	status = hvi_physmem_map_to_host(CLEAN_PHYS_ADDRESS64(pd[pdi]), PAGE_SIZE, 0, (void**)&pt);
	if (status)
		goto cleanup_and_leave;

	translation->page_size = PAGE_SIZE;
	translation->physical_address = CLEAN_PHYS_ADDRESS64(pt[pti]);
	status = STATUS_SUCCESS;

cleanup_and_leave:

	if (pml4 != NULL)
		hvi_physmem_unmap((void**)&pml4);

	if (pdp != NULL)
		hvi_physmem_unmap((void**)&pdp);

	if (pd != NULL)
		hvi_physmem_unmap((void**)&pd);

	if (pt != NULL)
		hvi_physmem_unmap((void**)&pt);

	return status;
}

static int _hvi_match_vdso(void* mapping)
{
	unsigned int delta;
	int matches;

	if (*(unsigned int*)mapping != 0x464c457f) /* .ELF */
		return 0;

	matches = 0;
	for (delta = 0; delta < PAGE_SIZE - 0x30; delta++) {
		if (!memcmp((char*)mapping + delta, "clock_gettime", strlen("clock_gettime"))) {
			matches++;
			continue;
		}

		if (!memcmp((char*)mapping + delta, "gettimeofday", strlen("gettimeofday"))) {
			matches++;
			continue;
		}

		if (!memcmp((char*)mapping + delta, "getcpu", strlen("getcpu"))) {
			matches++;
			continue;
		}

		if (matches == 3)
			break;
	}

	return (matches == 3);
}

static int _hvi_hook_vdso(void)
{
	int status;

	if (g_vdso_physical_address == 0)
		return STATUS_INVALID_INTERNAL_STATE;

	pr_info("will hook %llx\n", g_vdso_physical_address);

	status = hvi_set_ept_page_protection(g_vdso_physical_address, 1, 0, 1);
	if (status) {
		pr_err("hvi_set_ept_page_protection failed with status: %x\n", status);
		return status;
	} else {
		pr_info("successfully hooked first vdso page\n");
	}

	status = hvi_set_ept_page_protection(g_vdso_physical_address + PAGE_SIZE, 1, 0, 1);
	if (status) {
		pr_err("hvi_set_ept_page_protection failed with status: %x\n", status);
		return status;
	} else {
		pr_info("Successfully hooked second vdso page\n");
	}

	return STATUS_SUCCESS;
}

int disable_vdso_protection(void)
{
	int status;

	if (g_vdso_physical_address != 0) {
		pr_info("Will unhook %llx\n", g_vdso_physical_address);
		status = hvi_set_ept_page_protection(g_vdso_physical_address, 1, 1, 1);
		if (status) {
			pr_err("hvi_set_ept_page_protection failed with status: %x\n", status);
			return status;
		} else {
			pr_info("Sucessfully unhooked first vdso page\n");
		}

		status = hvi_set_ept_page_protection(g_vdso_physical_address + PAGE_SIZE, 1, 1, 1);
		if (status) {
			pr_err("hvi_set_ept_page_protection failed with status: %x\n", status);
			return status;
		} else {
			pr_info("Sucessfully unhooked second vdso page\n");
		}
	}

	return STATUS_SUCCESS;
}

static inline unsigned long __cr3_read(void)
{
	unsigned long long cr3;
	asm volatile("mov %%cr3, %%rax; mov %%rax, %0;" :"=m" (cr3) :: "%rax");
	return cr3;
}

int enable_vdso_protection(void)
{
	void* mapping;
	struct va_translation tr;
	int status;
	unsigned long long delta;

	tr.virtual_address = LINUX_KERNEL_START;
	tr.page_size = PAGE_SIZE;
	tr.physical_address = 0;

	for (;;) {
		status = hvi_translate_va(tr.virtual_address, __cr3_read(), &tr);
		if (status) {
			pr_err("hvi_translate_va failed: %x\n", status);
			return status;
		}

		for (delta = 0; delta < tr.page_size; delta += PAGE_SIZE) {
			int found = 0;
			status = hvi_physmem_map_to_host(tr.physical_address + delta, PAGE_SIZE, 0, &mapping);
			if (status) {
				pr_err("hvi_physmem_map_to_host failed: %x\n", status);
				return status;
			}

			found = _hvi_match_vdso(mapping);

			status = hvi_physmem_unmap((void**)&mapping);

			if (found) {
				g_vdso_physical_address = tr.physical_address + delta;
				pr_info("Found vdso at %llx %llx\n", tr.virtual_address + delta, tr.physical_address + delta);
				goto _hook_vdso;
			}
		}

		tr.virtual_address += tr.page_size;
	}

	pr_err("Vdso not found...\n");
	return status;

_hook_vdso:

	pr_info("Hooking vdso...\n");
	status =  _hvi_hook_vdso();
	if (status)
		pr_err("Failed hooking vdso..\n");

	return status;
}
