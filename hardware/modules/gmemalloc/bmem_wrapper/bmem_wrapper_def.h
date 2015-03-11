/*
 * bmem_wrapper_def.h
 *
 *  Created on: Apr 25, 2014
 *      Author: michael
 */

#ifndef BMEM_WRAPPER_DEF_H_
#define BMEM_WRAPPER_DEF_H_

#define MAX_STR_SIZE (50)
#define KLOG_TAG	"bmem_wrapper.c"

#ifndef KLOG_TAG
#define KLOG_TAG __FILE__
#endif

/* Error Logs */
#if 1
#define KLOG_E(fmt,args...) \
					do { printk(KERN_ERR "Error: [%s:%s:%d] "fmt"\n", KLOG_TAG, __func__, __LINE__, \
		    ##args); } \
					while (0)
#else
#define KLOG_E(x...) do {} while (0)
#endif

/* Debug Logs */
#if 1
#define KLOG_D(fmt,args...)  printk(KERN_DEBUG "[%s:%s:%d] "fmt"\n", KLOG_TAG, __func__, __LINE__, ##args); 
#else
#define KLOG_D(x...) do {} while (0)
#endif

/* Verbose Logs */
#if 0
#define KLOG_V(fmt,args...) \
					do { printk(KERN_INFO KLOG_TAG "[%s:%d] "fmt"\n", __func__, __LINE__, \
		    ##args); } \
					while (0)
#else
#define KLOG_V(x...) do {} while (0)
#endif



#define BMEM_PROC_PRINT_D(str, val) \
	if (bmem_proc_print_info(str, val, 0, &curr, &len, 500)) goto err;
#define BMEM_PROC_PRINT_X(str, val) \
		if (bmem_proc_print_info(str, val, 1, &curr, &len, 500)) goto err;
#define BMEM_PROC_PRINT_HDR(str) \
			if (bmem_proc_print_info(str, 0, 2, &curr, &len, 500)) goto err;


#define DMA_NOT_DONE         0
#define DMA_DONE_SUCCESS     1
#define DMA_DONE_FAILURE     2



/**
 * Typedefs
 */
//DMA CB
typedef struct {
	unsigned int m_transferInfo;
	void __user *m_pSourceAddr;
	void __user *m_pDestAddr;
	unsigned int m_xferLen;
	unsigned int m_tdStride;
	struct DmaControlBlock *m_pNext;
	unsigned int m_blank1, m_blank2;
} DmaControlBlock;
#endif /* BMEM_WRAPPER_DEF_H_ */
