#include "mem_tracker.h"
#include "interface.h"

#include <asm/traps.h>

#define TEST
static int command;
static unsigned long tlb_misses, readwss, writewss, unused;

typedef struct
{
	char flag;
	unsigned long addr;
	unsigned long count;
}PageInfo;

//######## Globals ##############
static PageInfo *miss_count = NULL;
static PageInfo *read_count = NULL;
static PageInfo *write_count = NULL;

//static unsigned long toppers[MAX_TOPPERS];
static unsigned long cr3;
static unsigned long startAddr;
static unsigned long numPages;
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
	command = buf[0] - '0';
	if(command < 0 || command > 2)
	{
		#ifdef TEST
		printk(KERN_INFO "In %s, Invalid command = [%d]", __FUNCTION__, command);
		#endif
		return 0;
	}
	else
	{
		#ifdef TEST
		printk(KERN_INFO "In %s, command = [%d]", __FUNCTION__, command);
		#endif
        	return count;
	}
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


void user_cr3(void)
{
        	__asm__ __volatile__("mov %%cr3, %0;"
                              :"=r" (cr3)
			      :
                              :"memory");


		#ifdef TEST
		printk(KERN_INFO "current cr3 = %lx\n", cr3);
		#endif

		cr3 |= (0x1UL << 11);

		#ifdef TEST
		printk(KERN_INFO "now cr3 = %lx\n", cr3);
		#endif

        	__asm__ __volatile__("mov %0, %%cr3;"
			      :
                              :"r" (cr3)
                              :"memory");
}

void kernel_cr3(void)
{
        	__asm__ __volatile__("mov %%cr3, %0;"
                              :"=r" (cr3)
			      :
                              :"memory");

		#ifdef TEST
		printk(KERN_INFO "kernel current cr3 = %lx\n", cr3);
		#endif

		cr3 &= ~(0x1UL << 11);

		#ifdef TEST
		printk(KERN_INFO "kernel now cr3 = %lx\n", cr3);
		#endif

        	__asm__ __volatile__("mov %0, %%cr3;"
			      :
                              :"r" (cr3)
                              :"memory");
}

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
		#ifdef TEST
                 printk(KERN_INFO "No vma yet\n");
		 #endif
                 goto nul_ret;
        }
       
        *addr_vma = (unsigned long) vma;

        pgd = pgd_offset(mm, address);
        if (pgd_none(*pgd) || unlikely(pgd_bad(*pgd)))
                goto nul_ret;
	#ifdef TEST
        printk(KERN_INFO "pgd(va) [%lx] pgd (pa) [%lx] *pgd [%lx]\n", (unsigned long)pgd, __pa(pgd), pgd->pgd); 
	#endif
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
	#ifdef TEST
        printk(KERN_INFO "pud(va) [%lx] pud (pa) [%lx] *pud [%lx]\n", (unsigned long)pud, __pa(pud), pud->pud); 
	#endif

        pmd = pmd_offset(pud, address);
        if (pmd_none(*pmd))
                goto nul_ret;
        if (unlikely(pmd_trans_huge(*pmd))){
		#ifdef TEST
                printk(KERN_INFO "I am huge\n");
		#endif
                goto nul_ret;
        }
	#ifdef TEST
        printk(KERN_INFO "pmd(va) [%lx] pmd (pa) [%lx] *pmd [%lx]\n", (unsigned long)pmd, __pa(pmd), pmd->pmd); 
	#endif
        ptep = pte_offset_map(pmd, address);
        if(!ptep){
		#ifdef TEST
                printk(KERN_INFO "pte_p is null\n\n");
		#endif
                goto nul_ret;
        }
	#ifdef TEST
        printk(KERN_INFO "pte(va) [%lx] pte (pa) [%lx] *pte [%lx]\n", (unsigned long)ptep, __pa(ptep), ptep->pte); 
	#endif
        return ptep;

        nul_ret:
		#ifdef TEST
               printk(KERN_INFO "Address could not be translated\n");
	       #endif
               return NULL;

}


static int fault_hook(struct mm_struct *mm, struct pt_regs *regs, unsigned long error_code, unsigned long address)
{
	unsigned long tmp = 15;
	//Hook will work only for given range of address
	if(((startAddr >> 12) <= (address>>12)) && ((endAddr >> 12) > (address>>12)))
	{
		//Walk through page table to get pte
        	gpte = get_pte(address, &vma);

		if(!gpte)	return -1;

		//Unpoison the entry
                gpte->pte &= ~(0x1UL << 50);

		if(command == 1)
		{
			//Read cr3 and set its 12th bit
        		__asm__ __volatile__("mov %%cr3, %0;"
                              :"=r" (cr3)
			      :
                              :"memory");

			cr3 |= (0x1UL << 11);

        		__asm__ __volatile__("mov %0, %%cr3;"
			      :
                              :"r" (cr3)
                              :"memory");
		}

		//Access the page to add its entry to tlb
		stac();
                //tmp = *(unsigned long *)address;
		*(unsigned long *)address = tmp;
		clac();


		if(command == 1)
		{
			//Reset 12th bit
			cr3 &= ~(0x1UL << 11);

        		__asm__ __volatile__("mov %0, %%cr3;"
			      :
                              :"r" (cr3)
                              :"memory");
		}

		//Poison the entry again
                gpte->pte |= (0x1UL << 50);

		//Update all the counters
                if(command != 2)	tlb_misses++;

		if(miss_count && read_count && write_count)	
		{
			int idx = (address - startAddr) >> 12;
			miss_count[idx].count++;
			if(error_code & X86_PF_WRITE)	write_count[idx].count++;
			else				read_count[idx].count++;
		}

		if(command == 2)
		{
			int i;
			unsigned long rtmp = 0;
			unsigned long wtmp = 0;
			unsigned long utmp = 0;
			for(i = 0; i < numPages; i++)
			{
				if(write_count[i].count > 0)		wtmp++;
				else if(read_count[i].count > 0)	rtmp++;
				else					utmp++;
			}
                        
			readwss = rtmp;
			writewss = wtmp;
			unused = utmp;
		}


		#ifdef TEST
                printk(KERN_INFO "Page fault till now [%ld]\n", tlb_misses);
		#endif
                return 0;
        }

        return -1;
}

int fill_toppers(struct read_command *cmd, PageInfo *count_ptr)
{
	int i, j;
	unsigned long max_idx;

	if(count_ptr == NULL)
	{
		cmd->valid_entries = 0;
		return -1;
	}

	//Use selection sort to get toppers
	for(i = 0; i < MAX_TOPPERS && i < numPages; i++)
	{
		max_idx = 0;
		while(count_ptr[max_idx].flag && max_idx < numPages)	max_idx++;

		for(j = 0; j < numPages; j++) 
		{
			if(!count_ptr[j].flag && count_ptr[j].count > count_ptr[max_idx].count)
				max_idx = j;
		}

		cmd->toppers[i].vaddr = count_ptr[max_idx].addr;
		cmd->toppers[i].count = count_ptr[max_idx].count;
		count_ptr[max_idx].flag = 1;
	}

	cmd->valid_entries = i;
	for(i = 0; i < numPages; i++)  count_ptr[i].flag = 0;

	return 0;
}

ssize_t handle_read(char *buff, size_t length)
{
	struct read_command *ptr1, *ptr2;
	struct read_command cmd;
	int i;

	//Size of the data must be correct
	if(length != sizeof(struct read_command))
        {
		#ifdef TEST
                printk(KERN_INFO "In %s. Length = [%ld] is not correct", __FUNCTION__, length);
		#endif
                return -1;
        }

	//Read command from user space
	stac();
	ptr1 = (struct read_command *)buff;
	cmd.command = ptr1->command;
	clac();

	ptr2 = &cmd;
	#ifdef TEST
	printk(KERN_INFO "In %s. command is [%ld]", __FUNCTION__, ptr2->command);
	#endif

	//calculate counters 
	switch(ptr2->command)
	{
		case FAULT_START:
			page_fault_pid = current->pid;
                	rsvd_fault_hook = fault_hook;
			#ifdef TEST
                	printk(KERN_INFO "In %s. Fault hook and pid is set", __FUNCTION__);
			#endif
			return 0;

		case TLBMISS_TOPPERS:
			fill_toppers(ptr2, miss_count);
			break;

		case READ_TOPPERS:
			fill_toppers(ptr2, read_count);
			break;

		case WRITE_TOPPERS:
			fill_toppers(ptr2, write_count);
			break;

		default:
			#ifdef TEST
			printk(KERN_INFO "In %s. Invalid command [%ld]", __FUNCTION__, ptr2->command);
			#endif
                	return -1;
	}

	stac();
        ptr1->valid_entries = ptr2->valid_entries;
	for(i = 0; i < MAX_TOPPERS; i++)	
	{
		ptr1->toppers[i].vaddr = ptr2->toppers[i].vaddr;
		ptr1->toppers[i].count = ptr2->toppers[i].count;
	}
        clac();

	return 0;
}

static void free_old_map(void)
{
	struct vm_area_struct *itr = NULL, *next = NULL;

	for(itr = old_map; itr != NULL; itr = next)
	{
		next = itr->vm_next;
		kfree(itr);
		itr = next;
	}

	old_map = NULL;
	#ifdef TEST
        printk(KERN_INFO "In %s. Old map is freed\n", __FUNCTION__);
	#endif
}

//Check using oldmap, whether any old map area has been merged to new mmap
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

	#ifdef TEST
	printk(KERN_INFO "In %s", __FUNCTION__);
	#endif

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
		#ifdef TEST
		printk(KERN_INFO "In %s. No mmap entry found for startAddr = [%lx]\n", 
				__FUNCTION__, startAddr);
		#endif
		return -1;
	}

	numPages = (endAddr - startAddr) >> 12; 
	#ifdef TEST
	printk(KERN_INFO "In %s. numPages = [%ld], endAddr = [%lx]\n", 
				__FUNCTION__, numPages, endAddr);
	#endif
	return 0;
}

//Free memory allocated for counters
void free_page_info(void)
{
	if(miss_count)	kfree(miss_count);

	miss_count = NULL;
	read_count = NULL;
	write_count = NULL;
}

//Malloc memory for counters
int malloc_page_info(void)
{
	int i;
	unsigned long addr;

	miss_count = kzalloc(sizeof(PageInfo) * numPages * 3, GFP_ATOMIC);
	if(miss_count == NULL)
	{
		#ifdef TEST
		printk(KERN_INFO "In %s. Cannot allocate memory for miss count\n", __FUNCTION__);
		#endif
		return -1;
	}

	read_count = miss_count + numPages;
	write_count = miss_count + numPages * 2;

	for(i = 0; i < numPages; i++)
	{
		addr = startAddr + (i << 12);
		miss_count[i].addr = addr;
		read_count[i].addr = addr;
		write_count[i].addr = addr;
	}

	return 0;
}

ssize_t handle_write(const char *buff, size_t length)
{
	long ptr;
	int i;

	//Write is accepting only long type inputs
	if(length != 8)	
	{
		#ifdef TEST
		printk(KERN_INFO "In %s. Length = [%ld] is not correct", __FUNCTION__, length);
		#endif
		return -1;
	}

	//Read the address provided by user
	stac();
	startAddr = *(long *)buff;
	clac();

	#ifdef TEST
	printk(KERN_INFO "In %s. startAddr = [%lx]\n", __FUNCTION__, startAddr);
	#endif

	//Calculate the number of pages in user provided mmap area
	if(find_num_pages() != 0)
	{
		#ifdef TEST
		printk(KERN_INFO "In %s. No entry in mmap found for startAddr = [%lx]\n", 
				__FUNCTION__, startAddr);
		#endif
		return -1;
	}

	if(malloc_page_info() < 0)	return -1;

	//Poison all the entries in user mmap area
	ptr = startAddr;
	for(i = 0; i < numPages; i++)
	{
        	gpte = get_pte(ptr, &vma);
        	if(gpte)    gpte->pte |= (0x1UL << 50);
		ptr += (1<<12);
	}

   	return 0;
}

//Read the current mmap data strcuture
static int read_mmap(void)
{
	struct vm_area_struct *itr, *ptr, *prev = NULL, *next;
	#ifdef TEST
	printk(KERN_INFO "In %s", __FUNCTION__);
	#endif

	//Loop through current mmap list
	for(itr = current->mm->mmap; itr != NULL; itr = itr->vm_next)
	{
		//Allocate node of linked list. Break if fails
		ptr = kzalloc(sizeof(struct vm_area_struct), GFP_ATOMIC);
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


	//If some alocation failed, then free already allocated memory
	if(ptr == NULL)
	{
		#ifdef TEST
		printk(KERN_INFO "In %s. Failed to allocate memory.\n", __FUNCTION__); 
		#endif

		//Free previously allocated memory
		for(ptr = old_map; ptr != NULL; ptr = next) 
		{
			next = old_map->vm_next;
			kfree(ptr);
		}
		old_map = NULL;
		return -1;
	}

	return 0;
}

void reset_counters(void)
{
	//Remove pag fault hook
	page_fault_pid = -1;
        rsvd_fault_hook = NULL;

	tlb_misses = 0;
	writewss = 0;
	readwss = 0;
	unused = 0;
	startAddr = 0;
	endAddr = 0;
	numPages = 0;
	gpte = 0;
}

int handle_open(void)
{
	#ifdef TEST
	printk(KERN_INFO "In %s", __FUNCTION__);
	#endif
	reset_counters();
	return read_mmap();
}

int handle_close(void)
{
	int i;
	long ptr;

	#ifdef TEST
	printk(KERN_INFO "In %s.\n", __FUNCTION__);
	#endif

	//Free old map if not already freed
	if(old_map)	free_old_map();
	free_page_info();

	//Unpoison all the user entries
	ptr = startAddr;
	for(i = 0; i < numPages; i++)
	{
		gpte = get_pte(ptr, &vma);
		if(gpte)    gpte->pte &= ~(0x1UL << 50);
		ptr += (1<<12);
	}

	//Remove pag fault hook
	page_fault_pid = -1;
        rsvd_fault_hook = NULL;
	//reset_counters();
   	return 0;
}
