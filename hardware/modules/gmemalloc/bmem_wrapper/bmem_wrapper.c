/*******************************************************************************
 * Copyright 2010 Broadcom Corporation.  All rights reserved.
 *
 *	@file	drivers/video/.../bmem_wrapper/bmem_wrapper.c
 *
 * Unless you and Broadcom execute a separate written software license agreement
 * governing use of this software, this software is licensed to you under the
 * terms of the GNU General Public License version 2, available at
 * http://www.gnu.org/copyleft/gpl.html (the "GPL").
 *
 * Notwithstanding the above, under no circumstances may you combine this
 * software in any way with any other Broadcom software provided under a license
 * other than the GPL, without Broadcom's express prior written consent.
 *******************************************************************************/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/types.h>
/* needed for __init,__exit directives */
#include <linux/init.h>
/* needed for remap_page_range */
#include <linux/mm.h>
/* obviously, for kmalloc */
#include <linux/slab.h>
/* for struct file_operations, register_chrdev() */
#include <linux/fs.h>

#include <linux/proc_fs.h>
/* standard error codes */
#include <linux/errno.h>

/* Race condition in kernel*/
#include <linux/semaphore.h>

/* this header files wraps some common module-space operations ...
 here we use mem_map_reserve() macro */
#include <linux/dma-mapping.h>
#include <linux/ioport.h>
#include <linux/list.h>
/* for current pid */
#include <linux/sched.h>

#include <asm/io.h>
#include <asm/uaccess.h>

#include <linux/broadcom/bcm_major.h>
#include <linux/broadcom/bmem_wrapper.h>
#include <linux/broadcom/bcm_gememalloc_ioctl.h>

#include <linux/broadcom/bcm_memalloc_wrapper.h>
#include <linux/broadcom/bcm_memalloc_ioctl.h>

#include <linux/android_pmem.h>
#include <linux/file.h>
#include <linux/debugfs.h>

#include <mach/dma.h>
#include <linux/pagemap.h>
#include "vc_support.h"
#include "bmem_wrapper_def.h"

#include <linux/proc_fs.h>

/* module description */
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Broadcom");

#define DRV_NAME "bmem"
#define DEV_NAME "bmem"

#define VIRT_TO_BUS_CACHE_SIZE 8

#define pgprot_cached(prot) \
__pgprot((pgprot_val(prot) & ~L_PTE_MT_MASK) | L_PTE_MT_WRITEBACK)

static int bmem_major = BCM_GEMEMALLOC_MAJOR;
//extern void *bmem_mempool_base;
static dma_addr_t dma_cohr_start_addr;
static struct semaphore bmem_sem;

static struct bmem_logic logic;
static bmem_status_t bmem_status;
static struct proc_dir_entry *bmem_proc_file;
static struct semaphore bmem_status_sem;

static MemallocwrapParams* hw_OutBuf = NULL;
static struct semaphore bmem_virt_list_sem;

//dma control
static unsigned int *g_pDmaChanBase;
static int g_dmaIrq;
static int g_dmaChan;

//user virtual to bus address translation acceleration
static unsigned long g_virtAddr[VIRT_TO_BUS_CACHE_SIZE];
static unsigned long g_busAddr[VIRT_TO_BUS_CACHE_SIZE];
static unsigned long g_cbVirtAddr;
static unsigned long g_cbBusAddr;
static int g_cacheInsertAt;
static int g_cacheHit, g_cacheMiss;

//off by default
static void __user *g_pMinPhys;
static void __user *g_pMaxPhys;
static unsigned long g_physOffset;

static unsigned int dmaDone = DMA_NOT_DONE;
struct completion dma_complete;

//cma allocation
static int g_cmaHandle;

/* Device variables */
static struct class* bmem_wrapper_class = NULL;
static struct device* bmem_wrapper_device = NULL;

static struct file_operations bmem_proc_fops;

void *v3d_mempool_base;
EXPORT_SYMBOL(v3d_mempool_base);

unsigned long v3d_mempool_size;
EXPORT_SYMBOL(v3d_mempool_size);

typedef struct {
	unsigned long busAddress;
	unsigned int size;
	char allocated;
	struct file *filp;
	/* Following needed only for pmem users calling CONNECT ioctl */
	char connected;
	int master_fd;
	struct file *master_filp;
} bmem_pmem_data_t;

typedef struct {
	BMEM_HDL bmem_handle;
	bmem_pmem_data_t bmem_pmem_data;
} bmem_wrapper_data_t;

/****** CACHE OPERATIONS ********/
static inline void FlushAddrCache(void) {
	int count = 0;
	for (count = 0; count < VIRT_TO_BUS_CACHE_SIZE; count++)
		g_virtAddr[count] = 0xffffffff;	//never going to match as we always chop the bottom bits anyway

	g_cbVirtAddr = 0xffffffff;

	g_cacheInsertAt = 0;
}

//translate from a user virtual address to a bus address by mapping the page
//NB this won't lock a page in memory, so to avoid potential paging issues using kernel logical addresses
static inline void __iomem *UserVirtualToBus(void __user *pUser) {
	int mapped;
	struct page *pPage;
	void *phys;

//map it (requiring that the pointer points to something that does not hang off the page boundary)
	mapped = get_user_pages(current, current->mm, (unsigned long) pUser, 1, 1,
			0, &pPage, 0);

	if (mapped <= 0)	//error
		return 0;

	printk(KERN_DEBUG "user virtual %p arm phys %p bus %p\n", pUser,
			page_address(pPage),
			(void __iomem *) __virt_to_bus(page_address(pPage)));

//get the arm physical address
	phys = page_address(pPage) + offset_in_page(pUser);
	page_cache_release(pPage);

//and now the bus address
	return (void __iomem *) __virt_to_bus(phys);
}

static inline void __iomem *UserVirtualToBusViaCbCache(void __user *pUser) {
	unsigned long virtual_page = (unsigned long) pUser & ~4095;
	unsigned long page_offset = (unsigned long) pUser & 4095;
	unsigned long bus_addr;

	if (g_cbVirtAddr == virtual_page) {
		bus_addr = g_cbBusAddr + page_offset;
		g_cacheHit++;
		return (void __iomem *) bus_addr;
	} else {
		bus_addr = (unsigned long) UserVirtualToBus(pUser);

		if (!bus_addr)
			return 0;

		g_cbVirtAddr = virtual_page;
		g_cbBusAddr = bus_addr & ~4095;
		g_cacheMiss++;

		return (void __iomem *) bus_addr;
	}
}

//do the same as above, by query our virt->bus cache
static inline void __iomem *UserVirtualToBusViaCache(void __user *pUser) {
	int count;
//get the page and its offset
	unsigned long virtual_page = (unsigned long) pUser & ~4095;
	unsigned long page_offset = (unsigned long) pUser & 4095;
	unsigned long bus_addr;

	if (pUser >= g_pMinPhys && pUser < g_pMaxPhys) {
		printk(KERN_DEBUG "user->phys passthrough on %p\n", pUser);
		return (void __iomem *) ((unsigned long) pUser + g_physOffset);
	}

//check the cache for our entry
	for (count = 0; count < VIRT_TO_BUS_CACHE_SIZE; count++)
		if (g_virtAddr[count] == virtual_page) {
			bus_addr = g_busAddr[count] + page_offset;
			g_cacheHit++;
			return (void __iomem *) bus_addr;
		}

//not found, look up manually and then insert its page address
	bus_addr = (unsigned long) UserVirtualToBus(pUser);

	if (!bus_addr)
		return 0;

	g_virtAddr[g_cacheInsertAt] = virtual_page;
	g_busAddr[g_cacheInsertAt] = bus_addr & ~4095;

//round robin
	g_cacheInsertAt++;
	if (g_cacheInsertAt == VIRT_TO_BUS_CACHE_SIZE)
		g_cacheInsertAt = 0;

	g_cacheMiss++;

	return (void __iomem *) bus_addr;
}
/*
 * bmem_pmem_connect()
 * Description : Used by pmem user. subregion file connects to a master file
 *		to share buffer allocated by the master
 */
static int bmem_pmem_connect(unsigned long master_fd, struct file *file) {
	bmem_wrapper_data_t *p_data = file->private_data;
	bmem_wrapper_data_t *p_master_data;
	struct file *master_file;
	int ret = 0, put_needed;

	/* retrieve the src file and check it is a pmem file with an alloc */
	master_file = fget_light(master_fd, &put_needed);
	KLOG_D("master_fd[%d] master_file[%p] subfile[%p], put_needed[%d]\n",
			(int)master_fd, master_file, file, put_needed);
	if (!master_file) {
		p_data->bmem_pmem_data.connected = -1;
		KLOG_E("pmem_connect: master file not found!\n");
		ret = -EINVAL;
		goto err_no_file;
	}
	p_master_data = master_file->private_data;
	if (p_master_data->bmem_pmem_data.allocated == 0) {
		p_data->bmem_pmem_data.connected = -1;
		KLOG_E("pmem_connect: master file has no alloc!\n");
		ret = -EINVAL;
		goto err_bad_file;
	}
	p_data->bmem_pmem_data.busAddress =
			p_master_data->bmem_pmem_data.busAddress;
	p_data->bmem_pmem_data.size = p_master_data->bmem_pmem_data.size;
	p_data->bmem_pmem_data.master_fd = master_fd;
	p_data->bmem_pmem_data.master_filp = master_file;
	p_data->bmem_pmem_data.allocated = p_master_data->bmem_pmem_data.allocated;
	p_data->bmem_pmem_data.connected = 1;

	err_bad_file: fput_light(master_file, put_needed);
	err_no_file: return ret;
}

/*
 * remove_from_virt_list()
 * Description : Used for removing entry from driver database used to maintain mapping
 *		of physical to user virtual mapping
 */
static int remove_from_virt_list(MemallocwrapParams* entry) {
	MemallocwrapParams* curr = hw_OutBuf;
	MemallocwrapParams *prev, *next;

	KLOG_D("Entry");
	if (entry == NULL) {
		KLOG_E("NULL entry passed");
		return 0;
	}

	if (hw_OutBuf == NULL) {
		KLOG_D("NULL hw_OutBuf");
		return 0;
	} else if (hw_OutBuf->virtualaddress == entry->virtualaddress) {
		next = hw_OutBuf->nextAddress;
		kfree(hw_OutBuf);
		hw_OutBuf = next;
		KLOG_D("Exit");
		return 1;
	} else {
		prev = hw_OutBuf;
		curr = hw_OutBuf->nextAddress;
		while (curr != NULL) {
			if (curr->virtualaddress == entry->virtualaddress) {
				prev->nextAddress = curr->nextAddress;
				kfree(curr);
				KLOG_D("Exit");
				return 1;
			}
			prev = curr;
			curr = curr->nextAddress;
		}
	}
	return 0;
}

/*
 * add_to_virt_list()
 * Description : Used for adding entry to driver database used to maintain mapping
 *		of physical to user virtual mapping
 */
static int add_to_virt_list(MemallocwrapParams* entry) {
	MemallocwrapParams* curr = hw_OutBuf;
	MemallocwrapParams* new_element;

	KLOG_D("Entry");
	if (entry == NULL) {
		KLOG_E("NULL entry passed");
		return 0;
	}

	new_element = (MemallocwrapParams*) kmalloc(sizeof(MemallocwrapParams),
	GFP_KERNEL | GFP_DMA);
	if (new_element == NULL) {
		KLOG_E("No memory - kmalloc");
		return 0;
	}
	new_element->busAddress = entry->busAddress;
	new_element->virtualaddress = entry->virtualaddress;
	new_element->size = entry->size;
	new_element->nextAddress = NULL;

	if (hw_OutBuf == NULL) {
		hw_OutBuf = new_element;
	} else {
		while (curr->nextAddress != NULL) {
			curr = curr->nextAddress;
		}
		curr->nextAddress = new_element;
	}
	KLOG_D("Exit");
	return 1;
}

/*
 * get_from_virt_list()
 * Description : Used for querying physical address corresponding to user virtual address
 *		from driver database used to maintain mapping of physical to user virtual mapping
 */
static unsigned long get_from_virt_list(unsigned long virtualaddress) {
	MemallocwrapParams* curr = hw_OutBuf;

	KLOG_D("Entry");
	while (curr != NULL) {
		if (curr->virtualaddress == virtualaddress) {
			KLOG_D("Exit");
			return curr->busAddress;
		}
		curr = curr->nextAddress;
	}

	KLOG_E("Item not found");
	return 0;
}

/*
 * is_mmap_for_pmem_interface()
 * Description : Used for checking whether mmap was called by pmem user or not.
 *		mmap of pmem user (master) expects to allocate memory if not yet allocated
 *		for the file.
 */
static int is_mmap_for_pmem_interface(struct file *file,
		struct vm_area_struct *vma) {
	return (0 == vma->vm_pgoff);
}

/*
 * is_pmem_alloc_needed()
 * Description : Used for checking whether pmem mmap needs to allocate.
 *		If owner file or master file has already allocated, we need to allocate again.
 *		Mapping of the already allocated buffer is what user expects.
 */
static int is_pmem_alloc_needed(struct file *file, struct vm_area_struct *vma) {
	bmem_wrapper_data_t *p_data = file->private_data;
	return (0 == p_data->bmem_pmem_data.allocated);
}

/*
 * pmem_alloc_done()
 * Description : Used for updating file context to mark that buffer is already
 *		allocated
 */
static void pmem_alloc_done(struct file *file, struct vm_area_struct *vma,
		unsigned long busAddress) {
	bmem_wrapper_data_t *p_data = file->private_data;

	p_data->bmem_pmem_data.busAddress = busAddress;
	p_data->bmem_pmem_data.size = vma->vm_end - vma->vm_start;
	p_data->bmem_pmem_data.filp = file;
	p_data->bmem_pmem_data.allocated = 1;
}

/*
 * bmem_print_status()
 * Description : Support function used to print the bmem heap status from kernel.
 */
static void bmem_print_status(void) {
	int result;

	if (logic.GetStatus == NULL) {
		KLOG_E("GetStatus() is NULL");
		goto err;
	}

	down(&bmem_sem);
	result = logic.GetStatus(&bmem_status);
	up(&bmem_sem);
	if (result) {
		KLOG_E("GetStatus failed form the proc call");
		goto err;
	}

	down(&bmem_status_sem);
	KLOG_E("\n  %-30s: ", "Current Usage Info");
	KLOG_E("\t%-30s: %d ", "Used space in bytes", bmem_status.total_used_space);
	KLOG_E("\t%-30s: %d ", "Free space in bytes", bmem_status.total_free_space);
	KLOG_E("\t%-30s: %d ", "Num Buffers in Use", bmem_status.num_buf_used);

	KLOG_E("  %-30s: ", "Statistics");
	KLOG_E("\t%-30s: %d ", "Maximum Memory usage", bmem_status.max_used_space);
	KLOG_E("\t%-30s: %d ", "Biggest Buffer Requested",
			bmem_status.biggest_buf_request);
	KLOG_E("\t%-30s: %d ", "Smallest Buffer Requested",
			bmem_status.smallest_buf_request);
	KLOG_E("\t%-30s: %d ", "Allocate Success Count",
			bmem_status.alloc_pass_cnt);
	KLOG_E("\t%-30s: %d ", "Mem Free Success Count", bmem_status.free_pass_cnt);

	KLOG_E("  %-30s: ", "Fragmentation Info");
	KLOG_E("\t%-30s: %d ", "Num Buffers Free", bmem_status.num_buf_free);
	KLOG_E("\t%-30s: %d ", "Biggest Buffer Available",
			bmem_status.biggest_chunk_avlbl);
	KLOG_E("\t%-30s: %d ", "Smallest Buffer Available",
			bmem_status.smallest_chunk_avlbl);
	KLOG_E("\t%-30s: %d ", "Max Num Holes occured",
			bmem_status.max_num_buf_free);
	KLOG_E("\t%-30s: %d ", "Max Fragmented", bmem_status.max_fragmented_size);

	KLOG_E("  %-30s: ", "Error Info");
	KLOG_E("\t%-30s: %d ", "Allocate Failures", bmem_status.alloc_fail_cnt);
	KLOG_E("\t%-30s: %d \n", "Mem Free Failures", bmem_status.free_fail_cnt);

	up(&bmem_status_sem);

	err: return;
}

/*
 * bmem_print_status()
 * Description : Support function used by proc interface to print info on
 *		the proc memory (proc read).
 *		0 - print value in integer format
 *		1 - print value in hex format
 *		2 - print header
 */
static int bmem_proc_print_info(char *str, int value, int print_type,
		char **curr, int *len, int max_cnt) {
	int str_len = 0;

	if (print_type == 0) {
		str_len = sprintf(*curr, "\t%-30s: %d \n", str, value);
	} else if (print_type == 1) {
		str_len = sprintf(*curr, "\t%-30s: 0x%08x \n", str, value);
	} else if (print_type == 2) {
		str_len = sprintf(*curr, "  %-30s: \n", str);
	}
	*curr += str_len;
	*len += str_len;
	if ((max_cnt - *len) < 100) {
		KLOG_E("proc size[%d] not sufficient. Only [%d] bytes written", max_cnt,
				*len);
		return 1;
	}
	return 0;
}

/*
 * bmem_proc_get_status()
 * Description : proc read callback to print the bmem heap status
 */
static int bmem_proc_get_status(char *page, char **start, off_t off, int count,
		int *eof, void *data) {
	char *curr = page;
	int len = 0;
	int result;

	KLOG_D("proc read has come: page[%p], off[%d], count[%d], data[%p] \n",
			page, (int)off, count, data);
	if (off != 0) {
		goto err;
	}

	if (logic.GetStatus == NULL) {
		KLOG_E("GetStatus() is NULL");
		goto err;
	}

	down(&bmem_sem);
	result = logic.GetStatus(&bmem_status);
	up(&bmem_sem);
	if (result) {
		KLOG_E("GetStatus failed form the proc call");
		goto err;
	}

	down(&bmem_status_sem);
	BMEM_PROC_PRINT_HDR("Current Usage Info");
	BMEM_PROC_PRINT_D("Used space in bytes", bmem_status.total_used_space);
	BMEM_PROC_PRINT_D("Free space in bytes", bmem_status.total_free_space);
	BMEM_PROC_PRINT_D("Num Buffers in Use", bmem_status.num_buf_used);

	BMEM_PROC_PRINT_HDR("Statistics");
	BMEM_PROC_PRINT_D("Maximum Memory usage", bmem_status.max_used_space);
	BMEM_PROC_PRINT_D("Biggest Buffer Requested",
			bmem_status.biggest_buf_request);
	BMEM_PROC_PRINT_D("Smallest Buffer Requested",
			bmem_status.smallest_buf_request);
	BMEM_PROC_PRINT_D("Allocate Success Count", bmem_status.alloc_pass_cnt);
	BMEM_PROC_PRINT_D("Mem Free Success Count", bmem_status.free_pass_cnt);

	BMEM_PROC_PRINT_HDR("Fragmentation Info");
	BMEM_PROC_PRINT_D("Num Buffers Free", bmem_status.num_buf_free);
	BMEM_PROC_PRINT_D("Biggest Buffer Available",
			bmem_status.biggest_chunk_avlbl);
	BMEM_PROC_PRINT_D("Smallest Buffer Available",
			bmem_status.smallest_chunk_avlbl);
	BMEM_PROC_PRINT_D("Max Num Holes occured", bmem_status.max_num_buf_free);
	BMEM_PROC_PRINT_D("Max Fragmented", bmem_status.max_fragmented_size);

	BMEM_PROC_PRINT_HDR("Error Info");
	BMEM_PROC_PRINT_D("Allocate Failures", bmem_status.alloc_fail_cnt);
	BMEM_PROC_PRINT_D("Mem Free Failures", bmem_status.free_fail_cnt);
	up(&bmem_status_sem);

	err: if (start) {
		*start = page;
	}
	if (eof) {
		*eof = 1;
	}
	return (len < count) ? len : count;
}

static int bmem_parse_string(const char *inputStr, u32 *opCode, u32 *arg) {
	int numArg;
	char tempStr[MAX_STR_SIZE];

	*opCode = 0;

	numArg = sscanf(inputStr, "%s%u", tempStr, arg);

	if (numArg < 1) {
		return -1;
	}

	if (strcmp(tempStr, "reset_statistics") == 0) {
		*opCode = 1;
	} else if (strcmp(tempStr, "1") == 0) {
		*opCode = 1;
	} else if (strcmp(tempStr, "reset_bmem") == 0) {
		*opCode = 2;
	} else if (strcmp(tempStr, "2") == 0) {
		*opCode = 2;
	} else if (strcmp(tempStr, "threshold") == 0) {
		*opCode = 3;
	} else if (strcmp(tempStr, "debug") == 0) {
		*opCode = 4;
	} else if (strcmp(tempStr, "stat") == 0) {
		*opCode = 5;
	}

	return 0;
}

/*
 * bmem_proc_set_status()
 * Description : proc write callback for multiple purposes
 *		1 or reset_statistics	- clear the min/max values to start statistics fresh
 *		2 or reset_bmem 		- reset the debug, stat levels and threshold
 *		threshold %d			- set the bmem threshold
 *		debug %d 				- set the debug level
 *			1 - Print on all alloc and free
 *			2 - Print fragmentation info on all alloc/free
 *			3 - Print entire heap partition on all alloc and free
 *		stat %d 				- set the statistics level
 *			1 - Do run-time fragmentation check on all alloc/free
 *			2 - Print entire heap partition on calls to get the status
 */
static int bmem_proc_set_status(struct file *file, const char *buffer,
		unsigned long count, void *data) {
	int result;
	bmem_set_status_t bmem_set_status;
	char inputStr[MAX_STR_SIZE];
	int len;
	u32 opCode = 0;
	u32 arg;

	if (logic.SetStatus == NULL) {
		KLOG_E("SetStatus() is NULL");
		goto err;
	}

	if (count > MAX_STR_SIZE)
		len = MAX_STR_SIZE;
	else
		len = count;
	if (copy_from_user(inputStr, buffer, len))
		return -EFAULT;

	inputStr[MAX_STR_SIZE - 3] = '\0';
	inputStr[MAX_STR_SIZE - 2] = ' ';
	inputStr[MAX_STR_SIZE - 1] = '0';
	bmem_parse_string(inputStr, &opCode, &arg);

	switch (opCode) {
	case 1:
		KLOG_D("Clearing max/min values in bmem status");
		down(&bmem_sem);
		bmem_set_status.cmd = BMEM_CLEAR_STAT;
		result = logic.SetStatus(&bmem_set_status);
		up(&bmem_sem);
		break;

	case 2:
		KLOG_D("Resetting the debug, stat levels and threshold");
		down(&bmem_sem);
		bmem_set_status.cmd = BMEM_RESET;
		result = logic.SetStatus(&bmem_set_status);
		up(&bmem_sem);
		break;

	case 3:
		KLOG_D("Setting the debug level to [%d]", arg);
		down(&bmem_sem);
		bmem_set_status.cmd = BMEM_SET_SMALL_CHUNK_THRESHOLD;
		bmem_set_status.data.chunk_threshold = arg;
		result = logic.SetStatus(&bmem_set_status);
		up(&bmem_sem);
		break;

	case 4:
		KLOG_D("Setting the debug level to [%d]", arg);
		down(&bmem_sem);
		bmem_set_status.cmd = BMEM_SET_DEBUG_LEVEL;
		bmem_set_status.data.debug_level = arg;
		result = logic.SetStatus(&bmem_set_status);
		up(&bmem_sem);
		break;

	case 5:
		KLOG_D("Setting the statistics level to [%d]", arg);
		down(&bmem_sem);
		bmem_set_status.cmd = BMEM_SET_STAT_LEVEL;
		bmem_set_status.data.stat_level = arg;
		result = logic.SetStatus(&bmem_set_status);
		up(&bmem_sem);
		break;

	default:
		KLOG_D(
				"1 or reset_statistics   - clear the min/max values to start statistics fresh");
		KLOG_D(
				"2 or reset_bmem         - reset the debug, stat levels and threshold");
		KLOG_D("threshold n             - set the threshold level");
		KLOG_D("debug n                 - set the debug level");
		KLOG_D("   1 - Print on all alloc and free");
		KLOG_D("   2 - fragmentation info on all alloc/free");
		KLOG_D("   3 - Print entire heap partition on all alloc and free");
		KLOG_D("stat n                  - set the statistics level");
		KLOG_D("   1 - Do run-time fragmentation check on all alloc/free");
		KLOG_D("   2 - Print entire heap partition on calls to get the status");
		break;
	}

	err: return count;
}

/*
 * bmem_wrapper_ioctl()
 * Description : ioctl implementation of the bmem driver
 */
static int bmem_wrapper_ioctl(struct file *filp, unsigned int cmd,
		unsigned long arg) {
	int result = -1;

//	KLOG_D("bmem_wrapper_ioctl: ioctl cmd 0x%08x\n", cmd);

	if (filp == NULL) {
		KLOG_E("filp found NULL");
		return -EFAULT;
	}
	/*
	 * extract the type and number bitfields, and don't decode
	 * wrong cmds: return ENOTTY (inappropriate ioctl) before access_ok()
	 */
	if ((_IOC_TYPE(cmd) != BMEM_WRAP_MAGIC)
			&& (_IOC_TYPE(cmd) != PMEM_IOCTL_MAGIC)
			&& (_IOC_TYPE(cmd) != HANTRO_WRAP_MAGIC)) {
		KLOG_E(
				"ioctl IOC_TYPE does not match expected [PMEM, GE, ME] magic : cmd[0x%08x]",
				cmd);
		return -ENOTTY;
	}

	/* ioctl number check disabled till all mem interfaces unified */
	if (_IOC_NR(cmd) > BMEM_WRAP_MAXNR) {
		KLOG_E("ioctl IOC_NR exceeds max[%d] : cmd[0x%08x]", BMEM_WRAP_MAXNR,
				cmd);
		return -ENOTTY;
	}

	if (_IOC_DIR(cmd) & _IOC_READ)
		result = !access_ok(VERIFY_WRITE, (void *)arg, _IOC_SIZE(cmd));
	else if (_IOC_DIR(cmd) & _IOC_WRITE)
		result = !access_ok(VERIFY_READ, (void *)arg, _IOC_SIZE(cmd));
	if (result) {
		KLOG_E("ioctl access type mismatch");
		return -EFAULT;
	}

//	KLOG_D("file[%p] cmd[0x%08x]", filp, cmd);

	switch (cmd) {

	case GEMEMALLOC_WRAP_ACQUIRE_BUFFER: {
		int ret = 0;
		bmem_wrapper_data_t *p_data = filp->private_data;
		GEMemallocwrapParams memparams;
		unsigned int page_aligned_size;

		ret = copy_from_user(&memparams, (const void *) arg, sizeof(memparams));
		if (ret != 0) {
			KLOG_E(
					"Error in copying user arguments in GEMEMALLOC_WRAP_ACQUIRE_BUFFER");
			return ret;
		}
		page_aligned_size = (((memparams.size + (PAGE_SIZE - 1)) >> PAGE_SHIFT)
				<< PAGE_SHIFT);
		if (memparams.size != page_aligned_size) {
			KLOG_D(
					"GEMEMALLOC_WRAP_ACQUIRE_BUFFER: size[0x%08x] made multiple of page size",
					memparams.size);
			memparams.size = page_aligned_size;
		}
		if (page_aligned_size == 0) {
			KLOG_E("Zero size alloction requested");
			memparams.busAddress = 0;
			result = -EINVAL;
		} else {
			if (logic.AllocMemory != NULL) {
				down(&bmem_sem);
				result = logic.AllocMemory(p_data->bmem_handle,
						&memparams.busAddress, memparams.size);
				up(&bmem_sem);
			} else {
				KLOG_E("AllocMemory() is NULL");
				memparams.busAddress = 0;
				result = 1;
			}
		}
		__copy_to_user((void *) arg, &memparams, sizeof(memparams));

		if (result) {
			KLOG_E(
					"GEMEMALLOC_WRAP_ACQUIRE_BUFFER: Allocate Failed for size[0x%08x]",
					memparams.size);
			bmem_print_status();
		} else {
//			KLOG_D("GEMEMALLOC_WRAP_ACQUIRE_BUFFER: addr[0x%08x] size[0x%08x]",
//					(int )memparams.busAddress, memparams.size);
		}
	}
		break;
	case GEMEMALLOC_WRAP_RELEASE_BUFFER: {
		bmem_wrapper_data_t *p_data = filp->private_data;
		unsigned long busaddr;

		__get_user(busaddr, (unsigned long * )arg);

		if (logic.FreeMemory != NULL) {
			down(&bmem_sem);
			result = logic.FreeMemory(p_data->bmem_handle, &busaddr);
			up(&bmem_sem);

		} else {
			KLOG_E("FreeMemory() is NULL");
			result = 1;
		}
		if (result) {
			KLOG_E(
					"GEMEMALLOC_WRAP_RELEASE_BUFFER: Free Failed for handle[%d] addr[0x%08x]",
					(int )p_data->bmem_handle, (int )busaddr);
		} else {
//			KLOG_D("GEMEMALLOC_WRAP_RELEASE_BUFFER: addr[0x%08x]",
//					(int )busaddr);
		}

	}
		break;
	case GEMEMALLOC_WRAP_COPY_BUFFER: {
		DmaStruct dma_buffers;
		DmaControlBlock aUserCB;
		void __iomem *pBusCB;

		KLOG_D("GEMEMALLOC_WRAP_COPY_BUFFER");

		int ret = 0;

		ret = copy_from_user(&dma_buffers, (const void *) arg,
				sizeof(dma_buffers));
		if (ret != 0) {
			printk(
					"Error in copying user arguments in GEMEMALLOC_WRAP_COPY_BUFFER");
			return ret;
		}

		/*Request the channel */
		g_dmaChan = bcm_dma_chan_alloc(BCM_DMA_FEATURE_FAST,
				(void **) &g_pDmaChanBase, &g_dmaIrq);
		if (ENODEV == g_dmaChan) {
			KLOG_E("---->Dma channel allocfailed for channel %d \n", 0);
			return -1;
		}

		KLOG_D("Channel num=%d\n", g_dmaChan);

		//reset the channel
		KLOG_D("allocated dma channel %d (%p), initial state %08x\n", result,
				g_pDmaChanBase, *g_pDmaChanBase);
		*g_pDmaChanBase = 1 << 31;

		KLOG_D("post-reset %08x\n", *g_pDmaChanBase);

		// Prepare DMA
		// TODO Complete
		aUserCB.m_pDestAddr = dma_buffers.dst_busAddr;
		pBusCB = 0;
		//pBusCB = UserVirtualToBusViaCbCache(&aUserCB);
		if (!pBusCB) {
			KLOG_E("virtual to bus translation failure for cb\n");
			return 1;
		}

		bcm_dma_start(g_pDmaChanBase, (dma_addr_t) pBusCB);

		//Allocate memory for array of pointers

	}
		break;
	case PMEM_GET_PHYS: {
		bmem_wrapper_data_t *p_data = filp->private_data;
		struct pmem_region region;

		if (p_data->bmem_pmem_data.allocated == 0) {
			region.offset = 0;
			region.len = 0;
		} else {
			region.offset = p_data->bmem_pmem_data.busAddress;
			region.len = p_data->bmem_pmem_data.size;
		}

		if (p_data->bmem_pmem_data.allocated == 0) {
			KLOG_E("GET_PHYS ioctl called without prior alloc/mmap");
		} else {
			KLOG_D("GET_PHYS ioctl addr[0x%08x] size[0x%08x]",
					(int)region.offset, (int)region.len);
		}

		if (copy_to_user((void __user *) arg, &region,
				sizeof(struct pmem_region)))
			return -EFAULT;
		result = 0;
	}
		break;
	case PMEM_CONNECT: {
		KLOG_D("PMEM_CONNECT ioctl request has come \n");
		result = bmem_pmem_connect(arg, filp);
	}
		break;
	case PMEM_MAP: {
		KLOG_D("PMEM_MAP ioctl : Dummy implementation \n");
		result = 0;
	}
		break;
	case PMEM_UNMAP:
	case PMEM_GET_SIZE:
	case PMEM_GET_TOTAL_SIZE:
	case PMEM_ALLOCATE:
	case PMEM_CACHE_FLUSH: {
		KLOG_E("pmem ioctl [0x%08x] currently not supported by this driver. \n",
				cmd);
		result = -1;
	}
		break;
	default: {
		KLOG_D("Invalid ioctl command : file[%p] cmd[0x%08x]", filp, cmd);
	}
		break;
	}
	return result;
}

/*
 * bmem_wrapper_open()
 * Description : open() implementation of the bmem driver
 */
static int bmem_wrapper_open(struct inode *inode, struct file *filp) {
	int r;

	bmem_wrapper_data_t *p_data = kmalloc(sizeof(bmem_wrapper_data_t),
	GFP_KERNEL);
	if (!p_data) {
		KLOG_E("kmalloc failed");
		return -ENOMEM;
	}

	filp->private_data = p_data;
	if (logic.open != NULL) {
		down(&bmem_sem);
		p_data->bmem_pmem_data.allocated = 0;
		p_data->bmem_pmem_data.filp = filp;
		p_data->bmem_pmem_data.connected = 0;
		p_data->bmem_pmem_data.master_fd = -1;
		p_data->bmem_pmem_data.master_filp = NULL;
		r = logic.open(&p_data->bmem_handle);
		up(&bmem_sem);
	} else {
		KLOG_E("open() is NULL");
		r = -1;
	}
//
//	KLOG_D("file[%p] handle[%p], return[%d]", filp, p_data->bmem_handle, r);

	return r;
}

/*
 * bmem_wrapper_release()
 * Description : close() implementation of the bmem driver.
 *		Would free all memories allocated using this file handle.
 */
static int bmem_wrapper_release(struct inode *inode, struct file *filp) {

	int r = 1;
	bmem_wrapper_data_t *p_data = filp->private_data;
//	KLOG_D("bmem_wrapper_release()");
//	KLOG_D("file[%p] handle[%p]", filp, p_data->bmem_handle);

	if ((p_data) && (logic.release)) {
		down(&bmem_sem);
		r = logic.release(p_data->bmem_handle);
		up(&bmem_sem);
	}

	if (p_data)
		kfree(p_data);

	return r;
}

/*
 * bmem_wrapper_mmap()
 * Description : mmap() implementation of the bmem driver
 *		Internally identifies the user (pmem or not) and acts accordingly.
 *		For pmem, cacheability is selected based on O_SYNC flag
 *		For others, mapping is done cacheable.
 */
static int bmem_wrapper_mmap(struct file *file, struct vm_area_struct *vma) {
	bmem_wrapper_data_t *p_data = file->private_data;
	int r;
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long busAddress;
	unsigned long page_aligned_size;

//	KLOG_D("mmap: file[%p] start[0x%08x], size[0x%08x] pgoff[0x%08x]", file,
//			(int )vma->vm_start, (int )size, (int )vma->vm_pgoff);
	if (((size >> PAGE_SHIFT) << PAGE_SHIFT) != size) {
		KLOG_E("size for mmap not multiple of page size");
	}

	if (logic.mmap != NULL) {
		down(&bmem_sem);
		r = logic.mmap(size, vma->vm_pgoff);
		up(&bmem_sem);
	} else {
		KLOG_E("mmap() is NULL");
		return -EFAULT;
	}

	if (0 == r) {
		/* mmap called for a acquire/free interface - valid pgoff (phys addr)
		 present which is already allocated */
		/* vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot); */
		vma->vm_page_prot = pgprot_cached(vma->vm_page_prot);

		/* Remap-pfn-range will mark the range VM_IO and VM_RESERVED */
		if (remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
				vma->vm_end - vma->vm_start, vma->vm_page_prot)) {
			KLOG_E(
					"acquire mmap failed: pgoff[0x%08x] virt[0x%08x] size[0x%08x]",
					(int )vma->vm_pgoff, (int )vma->vm_start,
					(int )(vma->vm_end - vma->vm_start));
			return -EAGAIN;
		}
//		KLOG_D("acquire mmap passed: pgoff[0x%08x] virt[0x%08x] size[0x%08x]",
//				(int)vma->vm_pgoff, (int)vma->vm_start,
//				(int)(vma->vm_end - vma->vm_start));
	} else if (is_mmap_for_pmem_interface(file, vma)) {
		/* mmap seems to be for pmem type of interface */
		KLOG_D("mmap for pmem: file[%p] start[0x%08x], size[0x%08x]", file,
				(int)vma->vm_start, (int)size);
		if (is_pmem_alloc_needed(file, vma)) {
			/* Seems to be the master file malloc request */
			busAddress = 0;
			page_aligned_size = (((size + (PAGE_SIZE - 1)) >> PAGE_SHIFT)
					<< PAGE_SHIFT);
			if (size != page_aligned_size) {
				KLOG_D(
						"Alloc for pmem: size[0x%08x] made multiple of page size",
						(int)size);
			}
			if (page_aligned_size == 0) {
				KLOG_E("Zero size alloction requested");
				busAddress = 0;
				return -EFAULT;
			}
			if (logic.AllocMemory != NULL) {
				down(&bmem_sem);
				r = logic.AllocMemory(p_data->bmem_handle, &busAddress,
						page_aligned_size);
				up(&bmem_sem);
			} else {
				KLOG_E("AllocMemory() is NULL");
				return -EAGAIN;
			}
			if (r) {
				KLOG_E("Allocation of memory for pmem failed for size[0x%08x]",
						(int )page_aligned_size);
				bmem_print_status();
				return -EAGAIN;
			}
			KLOG_D("Allocate memory for pmem: addr[0x%08x] size[0x%08x]",
					(int)busAddress, (int)page_aligned_size);
			pmem_alloc_done(file, vma, busAddress);
		} else {
			busAddress = p_data->bmem_pmem_data.busAddress;
			KLOG_D("Multiple mmaps for pmem from Hantro: addr[0x%08x]",
					(int)busAddress);
		}
		/* Setup the page tables for the mapping */
		vma->vm_pgoff = busAddress >> PAGE_SHIFT;
		if (file->f_flags & O_SYNC) {
			vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
			KLOG_D("set page tables in non-cached mode \n");
		} else {
			vma->vm_page_prot = pgprot_cached(vma->vm_page_prot);
			KLOG_D("set page tables in cached mode \n");
		}
		if (io_remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff, size,
				vma->vm_page_prot)) {
			KLOG_E("pmem mmap failed: pgoff[0x%08x] virt[0x%08x] size[0x%08x]",
					(int )vma->vm_pgoff, (int )vma->vm_start, (int )size);
			/* TODO: Free up allocated memory ??*/
			return -EAGAIN;
		}
		KLOG_D("pmem mmap passed: pgoff[0x%08x] virt[0x%08x] size[0x%08x]",
				(int)vma->vm_pgoff, (int)vma->vm_start, (int)size);
		r = 0;
	} else {
		KLOG_E("Invalid mmap params - nonzero[0x%x]pgoff, but not allocated",
				(int )vma->vm_pgoff);
		r = -1;
	}
	return r;
}

/* VFS methods */
static const struct file_operations bmem_wrapper_fops = { .open =
		bmem_wrapper_open, .release = bmem_wrapper_release, .unlocked_ioctl =
		bmem_wrapper_ioctl, .mmap = bmem_wrapper_mmap, };

/*
 * register_bmem_wrapper()
 * Description : bmem allocator module will register itself (callback functions)
 *		with the wrapper using this function
 */
int register_bmem_wrapper(struct bmem_logic *bmem_fops) {
	if (bmem_fops != NULL) {
		memcpy(&logic, bmem_fops, sizeof(logic));
	} else {
		KLOG_E("bmem_fops is NULL");
		return -1;
	}

	if (logic.init != NULL) {
		return logic.init(BMEM_SIZE, dma_cohr_start_addr);
	} else {
		KLOG_E("init() is NULL");
		return -1;
	}
}

EXPORT_SYMBOL(register_bmem_wrapper);

/*
 * register_bmem_wrapper()
 * Description : bmem allocator module will deregister itself from the wrapper
 */
void deregister_bmem_wrapper(void) {
	KLOG_D("Entry\n");
	if (logic.cleanup)
		logic.cleanup();
}

EXPORT_SYMBOL(deregister_bmem_wrapper);

/*
 * bmem_wrapper_init()
 * Description : Driver init function
 */
int __init bmem_wrapper_init(void) {
	int result;
	unsigned int pBusAddr;

	KLOG_D("Entry\n");
	result = register_chrdev(bmem_major, "gememalloc", &bmem_wrapper_fops);
	if (result < 0) {
		KLOG_E("unable to get major %d\n", bmem_major);
		return result;
	} else if (result != 0) { /* this is for dynamic major */
		bmem_major = result;
	}

	bmem_wrapper_class = class_create(THIS_MODULE, "gememalloc");
	if (IS_ERR(bmem_wrapper_class)) {
		KLOG_E("failed to register device class '%s'\n", "gememalloc");
		result = PTR_ERR(bmem_wrapper_class);
		return result;
	}

	/* With a class, the easiest way to instantiate a device is to call device_create() */
	bmem_wrapper_device = device_create(bmem_wrapper_class, NULL,
			MKDEV(bmem_major, 0), NULL, "gememalloc");
	if (IS_ERR(bmem_wrapper_device)) {
		KLOG_E("failed to create device '%s_%s'\n", "gememalloc", "gememalloc");
		result = PTR_ERR(bmem_wrapper_device);
		return result;
	}

	init_completion(&dma_complete);

	// Memory pool allocation of VC Memory
	v3d_mempool_size = 0;
	v3d_mempool_base = NULL;

	KLOG_D("allocating %ld bytes of VC memory\n", BMEM_SIZE);
	if (1
			== AllocateVcMemory(&g_cmaHandle, BMEM_SIZE, 4096,
					MEM_FLAG_L1_NONALLOCATING | MEM_FLAG_NO_INIT
							| MEM_FLAG_HINT_PERMALOCK)) {
		KLOG_E("failed to allocate %ld bytes of VC memory\n", BMEM_SIZE);
		g_cmaHandle = 0;
		return -EINVAL;
	}
	// VC memory allocated
	//get an address for it
	KLOG_D("trying to map VC memory\n");

	if (1 == LockVcMemory(&pBusAddr, g_cmaHandle)) {
		KLOG_E("failed to map CMA handle %d, releasing memory\n", g_cmaHandle);
		ReleaseVcMemory(g_cmaHandle);
		g_cmaHandle = 0;
		return -EINVAL;
	}

	KLOG_D("Bus address for CMA memory is 0x%x\n", pBusAddr);

	v3d_mempool_size = BMEM_SIZE;
	v3d_mempool_base = __bus_to_virt(pBusAddr);
	dma_cohr_start_addr = pBusAddr;	// pBusAddr;

	KLOG_D("v3d_mempool_size [0x%x]\n", v3d_mempool_size);
	KLOG_D("v3d_mempool_base [0x%x]\n", v3d_mempool_base);
	KLOG_D("dma_cohr_start_addr(BusAddr) [0x%x]\n", dma_cohr_start_addr);

// Mutex initialization
	sema_init(&bmem_sem, 1);
	sema_init(&bmem_status_sem, 1);
	sema_init(&bmem_virt_list_sem, 1);

// Proc sysfs creation
	bmem_proc_file = create_proc_entry(DEV_NAME, 0644, NULL);

	if (bmem_proc_file) {
		bmem_proc_file->data = NULL;
		bmem_proc_file->read_proc = bmem_proc_get_status;
		bmem_proc_file->write_proc = bmem_proc_set_status;
		// bmem_proc_file->owner = THIS_MODULE;
	} else {
		KLOG_E("Failed creating proc entry");
	}

	return 0;

	err: return result;
}

/*
 * bmem_wrapper_cleanup()
 * Description : Driver exit function
 */
void __exit bmem_wrapper_cleanup(void) {

	KLOG_D("Entry\n");

	unregister_chrdev(bmem_major, "gememalloc");
	if (bmem_proc_file) {
		remove_proc_entry(DEV_NAME, bmem_proc_file);
	}

	pr_notice("bmem_wrapper: module removed\n");
	return;
}

module_init(bmem_wrapper_init);
module_exit(bmem_wrapper_cleanup);

