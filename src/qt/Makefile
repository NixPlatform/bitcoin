.PHONY: FORCE
all: FORCE
        $(MAKE) -C .. nix_qt test_nix_qt
clean: FORCE
        $(MAKE) -C .. nix_qt_clean test_nix_qt_clean
check: FORCE
        $(MAKE) -C .. test_nix_qt_check
bitcoin-qt bitcoin-qt.exe: FORCE
         $(MAKE) -C .. nix_qt
