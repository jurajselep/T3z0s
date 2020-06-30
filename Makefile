MK_PATH:=$(abspath $(dir $(lastword $(MAKEFILE_LIST))))
T3Z0S_PATH:=${MK_PATH}
WIRESHARK_PATH:=${MK_PATH}/wireshark

############################################################
# Preparation steps, must be called as root :-(

.PHONY: root-symlink-of-lib
root-symlink-of-lib:
	cd /usr/lib && ln -fs "${T3Z0S_PATH}/t3z0s_rs/target/debug/libt3z0s_rs.a" .

.PHONY: clone-wireshark
clone-wireshark:
	if [ ! -d "${WIRESHARK_PATH}" ]; then git clone https://github.com/wireshark/wireshark.git "${WIRESHARK_PATH}" && cd "${WIRESHARK_PATH}" && git checkout b99a0c95d8c3fec834da0b7be27b2fc385054646; fi

.PHONY: patch-wireshark
patch-wireshark:
	cd "${WIRESHARK_PATH}" && if ! grep t3z0s CMakeLists.txt >/dev/null 2>/dev/null; then patch -p1 <"${T3Z0S_PATH}/wireshark.diff"; fi

.PHONY: symlink-for-wireshark
symlink-for-wireshark:
	cd "${WIRESHARK_PATH}" && cd plugins/epan && ln -fs "${T3Z0S_PATH}" t3z0s

.PHONY: call-bindgen
call-bindgen:
	cargo install bindgen
	cd "${WIRESHARK_PATH}" && rm -fv "${T3Z0S_PATH}/t3z0s_rs/src/wireshark/packet.rs" && bindgen "epan/packet.h" -o "${T3Z0S_PATH}/t3z0s_rs/src/wireshark/packet.rs" -- -I. $(shell pkg-config --cflags glib-2.0)

.PHONY: prepare
prepare: clone-wireshark patch-wireshark symlink-for-wireshark call-bindgen root-symlink-of-lib

############################################################
# Main part, building

.PHONY: build-t3z0s
build-t3z0s: call-bindgen
	cd "${T3Z0S_PATH}/t3z0s_rs" && cargo build

.PHONY: build-wireshark
build-wireshark:
	cd "${WIRESHARK_PATH}" && mkdir -p build && cd build && cmake .. && make

.PHONY: build
build: build-t3z0s build-wireshark

############################################################
# installing

.PHONY: install
install: build

############################################################
# cleaning

.PHONY: clean-t3z0s
clean-t3z0s:
	rm -fv "$WIRESHARK_PATH}/run/plugins/3.3/epan/t3z0s.so"

.PHONY: clean
clean: clean-t3z0s
	cd "${T3Z0S_PATH}/t3z0s_rs" && cargo clean
	if [ -e "${WIRESHARK_PATH}/build" ]; then cd "${WIRESHARK_PATH}/build" && make clean; fi

.PHONY: mrproper
mrproper: clean
	rm -vfr "${WIRESHARK_PATH}/build"
