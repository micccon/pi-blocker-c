SUBDIRS := layer_1 layer_2 layer_3 layer_4 layer_5 layer_6 layer_7

all: chmod-scripts
	@for d in $(SUBDIRS); do \
		if [ -f "$$d/Makefile" ] && grep -Eq "^[[:space:]]*all:" "$$d/Makefile"; then \
			echo "==> $$d: make all"; \
			$(MAKE) -C "$$d" all; \
		else \
			echo "==> $$d: skipping (no 'all' target)"; \
		fi; \
		done

chmod-scripts:
	@echo "==> setting executable permissions on start_layer*.sh scripts"
	@find . -type f -name 'start_layer*.sh' -exec chmod +x {} +

clean:
	@for d in $(SUBDIRS); do \
		if [ -f "$$d/Makefile" ] && grep -Eq "^[[:space:]]*clean:" "$$d/Makefile"; then \
			echo "==> $$d: make clean"; \
			$(MAKE) -C "$$d" clean; \
		else \
			echo "==> $$d: skipping (no 'clean' target)"; \
		fi; \
	done

run:
	@for d in $(SUBDIRS); do \
		if [ -f "$$d/Makefile" ] && grep -Eq "^[[:space:]]*run:" "$$d/Makefile"; then \
			echo "==> $$d: make run"; \
			$(MAKE) -C "$$d" run; \
		else \
			echo "==> $$d: skipping (no 'run' target)"; \
		fi; \
	done

rebuild: clean all

list:
	@printf "%s\n" $(SUBDIRS)

.PHONY: all clean run rebuild list chmod-scripts
