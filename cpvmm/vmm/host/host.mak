#############################################################################
# Copyright (c) 2013 Intel Corporation
#
#  Author:    John Manferdelli from previous eVMM makefiles
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#############################################################################

ifndef CPProgramDirectory
E=		/home/jlm/jlmcrypt
else
E=      	$(CPProgramDirectory)
endif
ifndef VMSourceDirectory
S=		/home/jlm/fpDev/fileProxy/cpvmm
else
S=      	$(VMSourceDirectory)
endif
ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
endif

# compile host library
# 	isr.c host_cpu.c vmm_globals.c policy_manager.c trial_exec.c

mainsrc=    $(S)/vmm/host

B=		$(E)/vmmobjects
BINDIR=	        $(B)/host
INCLUDES=	-I$(S)/common/include -I$(S)/vmm/include -I$(S)/common/hw \
    -I$(S)/common/include/arch -I$(S)/vmm/include/hw -I$(S)/common/include/platform \
    -I$(mainsrc)/hw -I$(S)/vmm/memory/ept
ASM_SRC = 	
DEBUG_CFLAGS:=  -Wall -Werror -Wno-format -g -DDEBUG -nostartfiles -nostdlib -nodefaultlibs
RELEASE_CFLAGS:= -Wall -Werror -Wno-unknown-pragmas -Wno-format -O3  -nostartfiles -nostdlib -nodefaultlibs
CFLAGS=     	$(RELEASE_CFLAGS) 
LDFLAGS= 	

CC=         gcc
LINK=       gcc
LIBMAKER=   libtool

dobjs=      $(BINDIR)/isr.o $(BINDIR)/host_cpu.o $(BINDIR)/vmm_globals.o \
	    $(BINDIR)/policy_manager.o $(BINDIR)/trial_exec.o

all: $(E)/libhost.a
 
$(E)/libhost.a: $(dobjs)
	@echo "libhost.a"
	$(LIBMAKER) -static -o $(E)/libhost.a $(dobjs)

$(BINDIR)/host_cpu.o: $(mainsrc)/host_cpu.c
	echo "host_cpu.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/host_cpu.o $(mainsrc)/host_cpu.c

$(BINDIR)/isr.o: $(mainsrc)/isr.c
	echo "isr.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/isr.o $(mainsrc)/isr.c

$(BINDIR)/vmm_globals.o: $(mainsrc)/vmm_globals.c
	echo "vmm_globals.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/vmm_globals.o $(mainsrc)/vmm_globals.c

$(BINDIR)/policy_manager.o: $(mainsrc)/policy_manager.c
	echo "policy_manager.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/policy_manager.o $(mainsrc)/policy_manager.c

$(BINDIR)/trial_exec.o: $(mainsrc)/trial_exec.c
	echo "trial_exec.o" 
	$(CC) $(CFLAGS) $(INCLUDES) -c -o $(BINDIR)/trial_exec.o $(mainsrc)/trial_exec.c

