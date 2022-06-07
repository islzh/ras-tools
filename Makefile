CFLAGS	= -O

all: mca-recover vtop cmcistorm hornet einj_mem_uc lmce rep_ce_page

clean:
	rm -f *.o mca-recover vtop cmcistorm hornet einj_mem_uc lmce rep_ce_page

mca-recover: mca-recover.c
	cc -o mca-recover $(CFLAGS) mca-recover.c

vtop: vtop.c
	cc -o vtop $(CFLAGS) vtop.c

cmcistorm: cmcistorm.o proc_pagemap.o
	cc -o cmcistorm $(CFLAGS) cmcistorm.o proc_pagemap.o

rep_ce_page: rep_ce_page.o proc_pagemap.o
	cc -o rep_ce_page $(CFLAGS) rep_ce_page.o proc_pagemap.o

hornet: hornet.c
	cc -o hornet $(CFLAGS) hornet.c

einj_mem_uc: einj_mem_uc.o proc_cpuinfo.o proc_interrupt.o proc_pagemap.o do_memcpy.o
	cc -o einj_mem_uc einj_mem_uc.o proc_cpuinfo.o proc_interrupt.o proc_pagemap.o do_memcpy.o

lmce: proc_pagemap.o lmce.o
	cc -o lmce proc_pagemap.o lmce.o -pthread
