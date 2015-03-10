obj-m += v3d_opt.o

V3D_SRC := $(shell pwd)

all:
	make -C $(KERNEL_DIR) M=$(V3D_SRC) modules

modules_install:
	make -C $(KERNEL_DIR) M=$(V3D_SRC) modules_install


