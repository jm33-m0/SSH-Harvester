all:
	${CC} -DOS_LINUX -DARCH_X86_64 ./ssh_harvester.c -o harvester.so -pie -fPIC -shared -nostdlib -nodefaultlibs -s
