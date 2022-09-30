# this is a make file for a kernel object

KERN_DIR = /lib/modules/$(shell uname -r)/build
NETHOOKS-OBJS = logging.o tcp_hook.o udp_hook.o icmp_hook.o nethooks.o filter.o proc.o nat.o

firewall-objs := $(NETHOOKS-OBJS) main.o

# will build "firewall.ko"
obj-m += firewall.o

all:
	make -C $(KERN_DIR) M=$(PWD) modules

clean:
	make -C $(KERN_DIR) M=$(PWD) clean
