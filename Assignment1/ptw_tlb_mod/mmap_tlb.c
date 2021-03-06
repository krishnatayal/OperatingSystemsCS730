#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<sys/fcntl.h>
#include<signal.h>
#include<sys/ioctl.h>
#include<sys/mman.h>
#include <sys/unistd.h>

int main()
{
   char *ptr, *ptr1;
   unsigned long ctr;
   char buf[64];
   int fd = open("/dev/demo",O_RDWR);
   if(fd < 0){
       perror("open");
       exit(-1);
   }

   ptr = mmap(NULL, 4096, PROT_READ|PROT_WRITE, MAP_ANONYMOUS|MAP_PRIVATE|MAP_POPULATE, 0, 0);
   if(ptr == MAP_FAILED){
        perror("mmap");
        exit(-1);
   }

   printf("Passing pointer %lx\n", (unsigned long)ptr);
   *((unsigned long *)buf) = (unsigned long)ptr;
   if(write(fd, buf, 8) < 0){
    perror("read");
    exit(-1);
   }
   
  *ptr = 100;
  
  if(read(fd, buf, 8) < 0){
     perror("read");
     exit(-1);
  }

  for(ctr=0; ctr<10; ++ctr){
      memset(ptr, 0, 4096);
      printf("Accessing #%ldth time\n", ctr+1);
  } 
  
  close(fd);    //Should be before munmap
  munmap((void *)ptr, 4096);
  return 0;
}
