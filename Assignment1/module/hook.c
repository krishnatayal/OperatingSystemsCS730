#include "mem_tracker.h"
#include "interface.h"

#include <asm/traps.h>

static int command;
static unsigned long tlb_misses, readwss, writewss, unused;

typedef struct
{
	long miss_count;
	long read_count;
	long write_count;
}PageInfo;

//######## Globals ##############
static PageInfo *page_info = NULL;
//static unsigned long toppers[MAX_TOPPERS];
static unsigned long startAddr;
static unsigned long numPages;
static unsigned long pfCount = 0;
static unsigned long endAddr;
struct vm_area_struct *old_map = NULL;
extern int page_fault_pid;
extern int (*rsvd_fault_hook)(struct mm_struct *mm, struct pt_regs *regs, unsigned long error_code, unsigned long address);

//static unsigned long gptr;
static pte_t *gpte;
static unsigned long vma;
//##############################


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


static pte_t* get_pte(unsigned long address, unsigned long *addr_vma)
{
        pgd_t *pgd;
        p4d_t *p4d;
        pud_t *pud;
        pmd_t *pmd;
        pte_t *ptep;
        struct mm_struct *mm = current->mm;
        struct vm_area_struct *vma = find_vma(mm, address);
        if(!vma){
                 printk(KERN_INFO "No vma yet\n");
                 goto nul_ret;
        }
       
        *addr_vma = (unsigned long) vma;

        pgd = pgd_offset(mm, address);
        if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
                goto nul_ret;
        printk(KERN_INFO "pgd(va) [%lx] pgd (pa) [%lx] *pgd [%lx]\n", (unsigned long)pgd, __pa(pgd), pgd->pgd); 
        p4d = p4d_offset(pgd, address);
        if (p4d_none(*p4d))
                goto nul_ret;
        if (unlikely(p4d_bad(*p4d)))
                goto nul_ret;
        pud = pud_offset(p4d, address);
        if (pud_none(*pud))
                goto nul_ret;
        if (unlikely(pud_bad(*pud)))
                goto nul_ret;
        printk(KERN_INFO "pud(va) [%lx] pud (pa) [%lx] *pud [%lx]\n", (unsigned long)pud, __pa(pud), pud->pud); 

        pmd = pmd_offset(pud, address);
        if (pmd_none(*pmd))
                goto nul_ret;
        if (unlikely(pmd_trans_huge(*pmd))){
                printk(KERN_INFO "I am huge\n");
                goto nul_ret;
        }
        printk(KERN_INFO "pmd(va) [%lx] pmd (pa) [%lx] *pmd [%lx]\n", (unsigned long)pmd, __pa(pmd), pmd->pmd); 
        ptep = pte_offset_map(pmd, address);
        if(!ptep){
                printk(KERN_INFO "pte_p is null\n\n");
                goto nul_ret;
        }
        printk(KERN_INFO "pte(va) [%lx] pte (pa) [%lx] *pte [%lx]\n", (unsigned long)ptep, __pa(ptep), ptep->pte); 
        return ptep;

        nul_ret:
               printk(KERN_INFO "Address could not be translated\n");
               return NULL;

}

static int fault_hook(struct mm_struct *mm, struct pt_regs *regs, unsigned long error_code, unsigned long address)
{
	//Hook will work only for given range of address
	if(((startAddr >> 12) <= (address>>12)) && ((endAddr >> 12) > (address>>12))
	 	&& (error_code & X86_PF_USER) ) 
	{
		//Walk through page table to get pte
        	gpte = get_pte(address, &vma);

		//Unpoison the entry
                gpte->pte &= ~(0x1UL << 50);

		//Access the page to add its entry to tlb
                *(unsigned long *)address = 17;

		//Poison the netry again
                gpte->pte |= (0x1UL << 50);

		//Update all the counters
                pfCount++;
		if(page_info)	
		{
			int idx = (endAddr - startAddr) >> 12;
			page_info[idx].miss_count++;
			if(error_code & X86_PF_WRITE)	page_info[idx].write_count++;
			else				page_info[idx].read_count++;
		}

                printk(KERN_INFO "PAGE Fault COUNT %ld\n", pfCount);
                return 0;
        }

        return -1;
}

#if 0
int fill_toppers(void)
{
	int i, j;
	unsigned long max_idx;

	if(page_info == NULL)	return -1;

	for(i = 0; i < MAX_TOPPERS && i < numPages; i++)
	{
		max_idx = i;

		for(j = i+1; j < numPages; j++) 
		{
			if(page_info[j].miss_count > page_info[max_idx].miss_count)
				max_idx = j;
		}

		toppers[i] = startAddr + max_idx * (1<<12);
	}

	for(; i < MAX_TOPPERS; i++)	toppers[i] = 0;

	return 0;
}
#endif

#define FILL_TOPPERS(count_type)	\
{					\
	int i, j;			\
	unsigned long max_idx;		\
						\
	if(page_info == NULL)			\
	{				\
                printk(KERN_INFO "In %s. page_info is null", __FUNCTION__);	\
		return -1;		\
	}				\
							\
	for(i = 0; i < MAX_TOPPERS && i < numPages; i++)	\
	{							\
		max_idx = i;				\
							\
		for(j = i+1; j < numPages; j++) 	\
		{						\
			if(page_info[j].count_type > page_info[max_idx].count_type)	\
				max_idx = j;					\
		}							\
									\
		ptr->toppers[i].vaddr = startAddr + max_idx * (1<<12);		\
		ptr->toppers[i].count = page_info[max_idx].count_type;	\
	}								\
									\
	for(; i < MAX_TOPPERS; i++)		\
	{					\
		ptr->toppers[i].vaddr = 0;		\
		ptr->toppers[i].count = 0;	\
	}				\
}

ssize_t handle_read(char *buff, size_t length)
{
	struct read_command *ptr;

	if(length != sizeof(struct read_command))
        {
                printk(KERN_INFO "In %s. Length = [%ld] is not correct", __FUNCTION__, length);
                return -1;
        }

	//TODO copy the user data to buffer using clac()
	ptr = (struct read_command *)buff;

	switch(ptr->command)
	{
	case FAULT_START:
		page_fault_pid = current->pid;
                rsvd_fault_hook = fault_hook;
                printk(KERN_INFO "In %s. Fault hook and pid is set", __FUNCTION__);
		break;

	case TLBMISS_TOPPERS:
		{
			FILL_TOPPERS(miss_count);
		}
		break;

	case READ_TOPPERS:
		{
			FILL_TOPPERS(read_count);
		}
		break;

	case WRITE_TOPPERS:
		{
			FILL_TOPPERS(write_count);
		}
		break;

	default:
		printk(KERN_INFO "In %s. Invalid command [%ld]", __FUNCTION__, ptr->command);
                return -1;
	}

#if 0
	else if(ptr->command == TLBMISS_TOPPERS)
	{
		FILL_TOPPERS(miss_count);
	}
	else if(ptr->command == READ_TOPPERS)
	{
		FILL_TOPPERS(read_count);
	}
	else if(ptr->command == WRITE_TOPPERS)
	{
		FILL_TOPPERS(write_count);
	}
	else
	{
                printk(KERN_INFO "In %s. Invalid command [%d]", __FUNCTION__, ptr->command);
		return -1;
	}
#endif
	//printk(KERN_INFO "Process pid [%d] cr3 [%lx]\n", current->pid, cr3);
        //gpte = get_pte(startAddr, &vma);
        //Krishna
        //gpte->pte |= 0x1UL << 50;
	//*(long *)buff = gpte->pte;

	return 0;
}

static void free_old_map(void)
{
	struct vm_area_struct *itr = NULL, *next = NULL;

	for(itr = old_map; itr != NULL; itr = next)
	{
		next = itr->vm_next;
		vfree(itr);
		itr = next;
	}

	old_map = NULL;
        printk(KERN_INFO "In %s. Old map is freed\n", __FUNCTION__);
}

static void check_size(void)
{
	struct vm_area_struct *itr = NULL;

	//Traverse through old map and get size of user mmap
	for(itr = old_map; itr != NULL; itr = itr->vm_next)
	{
		if(itr->vm_start > startAddr && itr->vm_start < endAddr)
			endAddr = itr->vm_start;
	}
}

static int find_num_pages(void)
{
	//Iterator on current mmap
	struct vm_area_struct *itr = NULL;

	printk(KERN_INFO "In %s", __FUNCTION__);
	//Iterate over current mmap and check where is the user provided address
	for(itr = current->mm->mmap; itr != NULL; itr = itr->vm_next)
	{
		if(startAddr >= itr->vm_start && startAddr < itr->vm_end)
		{
			endAddr = itr->vm_end;
			check_size();
			break;
		}
	}

	//Free the old map linked list.
	free_old_map();

	//No entry found for user provided address
	if(itr == NULL)	
	{
		printk(KERN_INFO "In %s. No mmap entry found for startAddr = [%lx]\n", 
				__FUNCTION__, startAddr);
		return -1;
	}

	numPages = (endAddr - startAddr) >> 12; 
	printk(KERN_INFO "In %s. numPages = [%ld], endAddr = [%lx]\n", 
				__FUNCTION__, numPages, endAddr);
	return 0;
}

ssize_t handle_write(const char *buff, size_t length)
{
	long ptr;
	int i;

	//Write is accepting only long type inputs
	if(length != 8)	
	{
		printk(KERN_INFO "In %s. Length = [%ld] is not correct", __FUNCTION__, length);
		return -1;
	}

	startAddr = *(long *)buff;
	printk(KERN_INFO "In %s. startAddr = [%lx]\n", __FUNCTION__, startAddr);

	//Calculate the number of pages in user provided mmap area
	if(find_num_pages() != 0)
	{
		printk(KERN_INFO "In %s. No entry in mmap found for startAddr = [%lx]\n", 
				__FUNCTION__, startAddr);
		return -1;
	}

	page_info = vzalloc(sizeof(PageInfo) * numPages);
	if(page_info == NULL)
	{
		printk(KERN_INFO "In %s. Cannot allocate memory for page info struct\n", __FUNCTION__);
		return -1;
	}

	//Poison all the entries in user mmap area
	ptr = startAddr;
	for(i = 0; i < numPages; i++)
	{
        	gpte = get_pte(ptr, &vma);
        	gpte->pte |= 0x1UL << 50;
		ptr += (1<<12);
	}

	//__native_tlb_flush_one_user(gptr);
   	return 0;
}

static int read_mmap(void)
{
	struct vm_area_struct *itr, *ptr, *prev = NULL, *next;
	printk(KERN_INFO "In %s", __FUNCTION__);

	//Loop through current mmap list
	for(itr = current->mm->mmap; itr != NULL; itr = itr->vm_next)
	{
		//Allocate node of linked list. Break if fails
		ptr = vzalloc(sizeof(struct vm_area_struct));
		if(ptr == NULL)	break;

		//Set head of linked list
		if(!old_map) old_map = ptr;

		//Save mmap info in newly allocated node
		ptr->vm_start = itr->vm_start;
		ptr->vm_end = itr->vm_end;
		ptr->vm_prev = prev;
		ptr->vm_next = NULL;
		if(prev) prev->vm_next = ptr;
		prev = ptr;
	}


	if(ptr == NULL)
	{
		printk(KERN_INFO "In %s. Failed to allocate memory.\n", __FUNCTION__); 

		//Free previously allocated memory
		for(ptr = old_map; ptr != NULL; ptr = next) 
		{
			next = old_map->vm_next;
			vfree(ptr);
		}
		old_map = NULL;
		return -1;
	}

	return 0;
}

int handle_open(void)
{
	printk(KERN_INFO "In %s", __FUNCTION__);
	pfCount = 0;
	startAddr = 0;
	endAddr = 0;
	return read_mmap();
}

int handle_close(void)
{
	int i;
	long ptr;

	printk(KERN_INFO "In %s.\n", __FUNCTION__);

	//Free old map if not already freed
	if(old_map)	free_old_map();

	if(page_info)	vfree(page_info);

	//Unpoison all the user entries
	ptr = startAddr;
	for(i = 0; i < numPages; i++)
	{
		gpte = get_pte(ptr, &vma);
		gpte->pte &= ~(0x1UL << 50);
		ptr += (1<<12);
	}

	//Remove pag fault hook
	page_fault_pid = -1;
        rsvd_fault_hook = NULL;

	//Reset user address info
	startAddr = 0;
	endAddr = 0;
	numPages = 0;

	//Reset counters
	gpte = 0;
	pfCount = 0;

   	return 0;
}
