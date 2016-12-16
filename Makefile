KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
#CFLAGS:=-DCONFIG_CHAINED_HOOKS  
LDD := /lib/modules/$(shell uname -r)/kernel/drivers/lka/

OBJS := khfilter.o
OBJS += khrules.o
TARGET := lkafilter


obj-m += $(TARGET).o
$(TARGET)-objs := $(OBJS) 


all: run clean


run:  clean load

compile:
	@$(MAKE) -C $(KDIR) M=$(PWD) modules 

#build:	compile

build:
	@$(MAKE) -C $(KDIR) M=$(PWD) modules

load:	compile
	@echo "try \"tail -f /var/log/messages\" in another window as root"
	-su -c "insmod ./$(TARGET).ko dolog=1";
#	-su -c "insmod ./$(TARGET).ko";


unload: 
	-su -c "rmmod $(TARGET);";

clean: unload
	-@rm -fr .*.*o* *.*o* .$(TARGET).* .tmp_versions* [mM]odule*	
#	-@rm -fr $(OBJ).o $(OBJ).ko $(TARGET).* .$(TARGET).*  [mM]odule*
