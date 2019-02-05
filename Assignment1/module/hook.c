#include "mem_tracker.h"
#include "interface.h"

static int command;
static unsigned long tlb_misses, readwss, writewss, unused;
static long startAddr;
//static long endAddr;
extern int page_fault_pid;
extern int (*rsvd_fault_hook)(struct mm_struct *mm, struct pt_regs *regs, unsigned long error_code, unsigned long address);



static ssize_t memtrack_command_show(struct kobject *kobj,
                                  struct kobj_attribute *attr, char *buf)
{
        return sprintf(buf, "%d\n", command);
}

static ssize_t memtrack_command_set(struct kobject *kobj,
                                   struct kobj_attribute *attr,
                                   const char *buf, size_t count)
{
        /*TODO    Part of assignment, needed to be implemented by you*/
        return count;
}

static struct kobj_attribute memtrack_command_attribute = __ATTR(command,0644,memtrack_command_show, memtrack_command_set);

static ssize_t memtrack_tlb_misses_show(struct kobject *kobj,
                                  struct kobj_attribute *attr, char *buf)
{
        return sprintf(buf, "%lu\n", tlb_misses);
}
static struct kobj_attribute memtrack_tlb_misses_attribute = __ATTR(tlb_misses, 0444,memtrack_tlb_misses_show, NULL);

static ssize_t memtrack_readwss_show(struct kobject *kobj,
                                  struct kobj_attribute *attr, char *buf)
{
        return sprintf(buf, "%lu\n", readwss);
}
static struct kobj_attribute memtrack_readwss_attribute = __ATTR(readwss, 0444,memtrack_readwss_show, NULL);

static ssize_t memtrack_writewss_show(struct kobject *kobj,
                                  struct kobj_attribute *attr, char *buf)
{
        return sprintf(buf, "%lu\n", writewss);
}
static struct kobj_attribute memtrack_writewss_attribute = __ATTR(writewss, 0444,memtrack_writewss_show, NULL);


static ssize_t memtrack_unused_show(struct kobject *kobj,
                                  struct kobj_attribute *attr, char *buf)
{
        return sprintf(buf, "%lu\n", unused);
}
static struct kobj_attribute memtrack_unused_attribute = __ATTR(unused, 0444,memtrack_unused_show, NULL);
static struct attribute *memtrack_attrs[] = {
        &memtrack_command_attribute.attr,
        &memtrack_tlb_misses_attribute.attr,
        &memtrack_readwss_attribute.attr,
        &memtrack_writewss_attribute.attr,
        &memtrack_unused_attribute.attr,
        NULL,
};
struct attribute_group memtrack_attr_group = {
        .attrs = memtrack_attrs,
        .name = "memtrack",
};



static int fault_hook(struct mm_struct *mm, struct pt_regs *regs, unsigned long error_code, unsigned long address)
{
   /*TODO Fault handler*/
    return 0;
}

ssize_t handle_read(char *buff, size_t length)
{
	if(length != 8)
        {
                //printk(KERN_INFO "In %s. Length = [%ld] is not correct", __FUNCTION__, length);
                return -1;
        }

	*(long *)buff = startAddr;

   return 0;
}


ssize_t handle_write(const char *buff, size_t length)
{
	if(length != 8)	
	{
		//printk(KERN_INFO "In %s. Length = [%ld] is not correct", __FUNCTION__, length);
		return -1;
	}

	startAddr = *(long *)buff;
	//__native_tlb_flush_one_user(gptr);
   	return 0;
}

int handle_open(void)
{
	//page_fault_pid = current->pid;
	//rsvd_fault_hook = fault_hook; 
	//printk(KERN_INFO "In %s. page_fault_pid = %d, rsvd_fault_hook = %p\n", __FUNCTION__,
	//		page_fault_pid, rsvd_fault_hook);
	return 0;
}

int handle_close(void)
{
	//page_fault_pid = -1;
        //rsvd_fault_hook = NULL;
	startAddr = 0;
	//printk(KERN_INFO "In %s. page_fault_pid = %d, rsvd_fault_hook = %p\n", __FUNCTION__, 
	//		page_fault_pid, rsvd_fault_hook);
   	return 0;
}