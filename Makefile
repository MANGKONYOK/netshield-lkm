# ==============================================================================
# NetShield-LKM: In-Kernel Network Packet Filter
# Build System: Linux Kernel Build System (Kbuild)
# Target Architecture: x86-64 / Linux
# ==============================================================================

# Module and object definitions
SHELL         := /bin/bash
MODULE_NAME   := netshield
obj-m         := $(MODULE_NAME).o
$(MODULE_NAME)-objs := src/netshield.o

# Compiler flags for kernel compilation
ccflags-y     := -I$(src)/src -Wall -Wextra -O2

# Kernel build directory detection
KVERSION      ?= $(shell uname -r)
KDIR          ?= /lib/modules/$(KVERSION)/build
PWD           := $(shell pwd)

# Terminal output colors
COLOR_RESET   := \033[0m
COLOR_GREEN   := \033[1;32m
COLOR_RED     := \033[1;31m
COLOR_YELLOW  := \033[1;33m
COLOR_BLUE    := \033[1;34m
COLOR_CYAN    := \033[1;36m

.PHONY: all clean load unload reload status test help check-headers

# Default target: compile the kernel module
all: check-headers
	@echo -e "$(COLOR_CYAN)[*] Compiling NetShield-LKM for Linux $(KVERSION)...$(COLOR_RESET)"
	$(MAKE) -C $(KDIR) M=$(PWD) modules
	@echo -e "$(COLOR_GREEN)[+] Build complete: $(MODULE_NAME).ko$(COLOR_RESET)"

# Verify kernel build directory presence before building
check-headers:
	@if [ ! -d "$(KDIR)" ]; then \
		echo -e "$(COLOR_RED)[!] Error: Kernel headers directory not found at $(KDIR)$(COLOR_RESET)"; \
		echo -e "$(COLOR_YELLOW)[i] To install headers on Debian/Kali Linux, run:$(COLOR_RESET)"; \
		echo -e "    sudo apt update && sudo apt install -y linux-headers-$(KVERSION)"; \
		echo -e "$(COLOR_YELLOW)[i] Alternatively, specify custom KDIR: make KDIR=/path/to/linux/build$(COLOR_RESET)"; \
		exit 1; \
	fi

# Clean build artifacts
clean:
	@echo -e "$(COLOR_CYAN)[*] Cleaning build artifacts...$(COLOR_RESET)"
	@if [ -d "$(KDIR)" ]; then \
		$(MAKE) -C $(KDIR) M=$(PWD) clean 2>/dev/null || true; \
	fi
	@rm -f src/*.o src/*.cmd src/.*.cmd src/*.mod.c src/*.mod
	@rm -f *.o *.ko *.mod *.mod.c *.mod.o *.order *.symvers .*.cmd
	@rm -rf .tmp_versions
	@echo -e "$(COLOR_GREEN)[+] Clean complete.$(COLOR_RESET)"

# Load the kernel module using the helper script
load:
	@chmod +x scripts/load_module.sh
	@sudo ./scripts/load_module.sh

# Unload the kernel module
unload:
	@echo -e "$(COLOR_CYAN)[*] Unloading $(MODULE_NAME)...$(COLOR_RESET)"
	@if lsmod | grep -q "^$(MODULE_NAME) "; then \
		sudo rmmod $(MODULE_NAME) && echo -e "$(COLOR_GREEN)[+] Successfully removed $(MODULE_NAME).$(COLOR_RESET)"; \
	else \
		echo -e "$(COLOR_YELLOW)[!] Module $(MODULE_NAME) is not currently loaded.$(COLOR_RESET)"; \
	fi

# Reload the kernel module
reload: unload
	@sleep 1
	@$(MAKE) load

# Inspect module status and sysfs parameters
status:
	@echo -e "$(COLOR_BLUE)=== NetShield-LKM Status ===$(COLOR_RESET)"
	@if lsmod | grep -q "^$(MODULE_NAME) "; then \
		echo -e "Module State: $(COLOR_GREEN)LOADED$(COLOR_RESET)"; \
		lsmod | grep "^$(MODULE_NAME) "; \
		echo -e "\n$(COLOR_BLUE)=== Sysfs Parameter Configuration ===$(COLOR_RESET)"; \
		if [ -d "/sys/module/$(MODULE_NAME)/parameters" ]; then \
			for p in /sys/module/$(MODULE_NAME)/parameters/*; do \
				param_name=$$(basename "$$p"); \
				param_val=$$(cat "$$p" 2>/dev/null || echo "N/A"); \
				echo -e "  $$param_name: $(COLOR_CYAN)$$param_val$(COLOR_RESET)"; \
			done; \
		fi; \
		echo -e "\n$(COLOR_BLUE)=== Recent Kernel Logs ([NetShield-LKM]) ===$(COLOR_RESET)"; \
		sudo dmesg | grep "\[NetShield-LKM\]" | tail -n 10 || true; \
	else \
		echo -e "Module State: $(COLOR_RED)NOT LOADED$(COLOR_RESET)"; \
	fi

# Run the comprehensive traffic and audit test suite
test:
	@chmod +x scripts/test_traffic.sh
	@sudo ./scripts/test_traffic.sh

# Display help information
help:
	@echo -e "$(COLOR_CYAN)NetShield-LKM Build & Management Utility$(COLOR_RESET)"
	@echo -e "Usage: make [target]"
	@echo -e ""
	@echo -e "Targets:"
	@echo -e "  all           - Compile the kernel module (default)"
	@echo -e "  clean         - Remove all compiled objects and temporary files"
	@echo -e "  load          - Load module into kernel via scripts/load_module.sh"
	@echo -e "  unload        - Safely remove module from kernel via rmmod"
	@echo -e "  reload        - Safely unload and reload the module"
	@echo -e "  status        - Check module load status and view sysfs parameters"
	@echo -e "  test          - Execute automated test suite via scripts/test_traffic.sh"
	@echo -e "  help          - Display this guidance text"