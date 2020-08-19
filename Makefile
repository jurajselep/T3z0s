SHELL:=/bin/bash

MK_PATH:=$(abspath $(dir $(lastword $(MAKEFILE_LIST))))
TEZOS_PATH:=${MK_PATH}
WIRESHARK_PATH:=${MK_PATH}/wireshark
WIRESHARK_OPT_PATH:=${MK_PATH}/opt
WIRESHARK_BIN_PATH:=${WIRESHARK_OPT_PATH}/bin

############################################################
# Preparation steps

.PHONY: clone-wireshark
clone-wireshark:
	if [ ! -d "${WIRESHARK_PATH}" ]; then \
		git clone https://github.com/wireshark/wireshark.git "${WIRESHARK_PATH}" && \
		cd "${WIRESHARK_PATH}" && \
		git checkout b99a0c95d8c3fec834da0b7be27b2fc385054646; \
	fi

.PHONY: patch-wireshark
patch-wireshark:
	cd "${WIRESHARK_PATH}" && if ! grep tezos CMakeLists.txt >/dev/null 2>/dev/null; then patch -p1 <"${TEZOS_PATH}/wireshark.diff"; fi

.PHONY: symlink-for-wireshark
symlink-for-wireshark:
	cd "${WIRESHARK_PATH}" && cd plugins/epan && ln -fs "${TEZOS_PATH}" tezos

.PHONY: call-bindgen
call-bindgen:
	cd "${WIRESHARK_PATH}" && rm -fv "${TEZOS_PATH}/tezos_rs/src/wireshark/packet.rs" && bindgen --no-rustfmt-bindings "epan/packet.h" -o "${TEZOS_PATH}/tezos_rs/src/wireshark/packet.rs" -- -I. $(shell pkg-config --cflags glib-2.0)
	cd "${WIRESHARK_PATH}" && rustfmt "${TEZOS_PATH}/tezos_rs/src/wireshark/packet.rs"

.PHONY: prepare
prepare: clone-wireshark patch-wireshark symlink-for-wireshark call-bindgen

############################################################
# Main part, building

.PHONY: build-tezos
build-tezos: call-bindgen
	cd "${TEZOS_PATH}/tezos_rs" && cargo build

.PHONY: symlink-of-lib
symlink-of-lib:
	mkdir -p "${WIRESHARK_PATH}/build/run" && cd "${WIRESHARK_PATH}/build/run" && ln -fs "${TEZOS_PATH}/tezos_rs/target/debug/libtezos_rs.a" .

.PHONY: build-wireshark
build-wireshark: symlink-of-lib
	cd "${WIRESHARK_PATH}" && mkdir -p build && cd build && cmake .. -DCMAKE_INSTALL_PREFIX="${WIRESHARK_OPT_PATH}" && make -j16

.PHONY: build
build: build-tezos build-wireshark

############################################################
# installing

.PHONY: install
install: build
	cd "${WIRESHARK_PATH}" && cd build && make install

.PHONY: sbit-for-dumpcat
# This requires root privileges
sbit-for-dumpcat:
	cd "${WIRESHARK_BIN_PATH}" && chown root.root dumpcap && chmod u+s dumpcap

############################################################
# cleaning

.PHONY: clean-tezos
clean-tezos:
	rm -fv "${WIRESHARK_PATH}/run/plugins/3.3/epan/tezos.so"

.PHONY: clean
clean: clean-tezos
	cd "${TEZOS_PATH}/tezos_rs" && cargo clean
	if [ -e "${WIRESHARK_PATH}/build" ]; then cd "${WIRESHARK_PATH}/build" && make clean; fi

.PHONY: mrproper
mrproper: clean
	rm -vfr "${WIRESHARK_PATH}/build"

############################################################
# tests

.PHONY: test-tshark-over-pcap
test-tshark-over-pcap:
	tests/tools/tshark-over-pcap.sh

.PHONY: test
test: test-tshark-over-pcap


.bin/carthagenet.sh:
	mkdir -p .bin
	wget -O .bin/carthagenet.sh https://gitlab.com/tezos/tezos/raw/latest-release/scripts/tezos-docker-manager.sh
	chmod u+x .bin/carthagenet.sh

.PHONY: check-docker-test-image
check-docker-test-image:
	if ! grep 'tezos[/]test:latest' <(docker images --format '{{.Repository}}:{{.Tag}}'); then \
		${MAKE} test-docker-image; \
	fi

.PHONY: install-cmp-json-and-tshark
install-cmp-json-and-tshark:
	cd tests/tshark-with-ocaml-node/cmp-json-and-tshark && cargo install --path . --root ..

.PHONY: test-tshark-with-carthagenet
test-tshark-with-carthagenet:
	#cd tests/tshark-with-ocaml-node && docker-compose --verbose up
	cd tests/tshark-with-ocaml-node && docker-compose rm --force || true
	cd tests/tshark-with-ocaml-node && docker-compose up
	# docker-compose down

############################################################
# docker-images

.PHONY: rust-nightly-docker-image
rust-nightly-docker-image:
	docker build dockers/rust-nightly-20200726 -t meavelabs/rust:nightly-20200726

.PHONY: test-docker-image
test-docker-image: clone-wireshark
	docker build . -t meavelabs/tshark:latest

.PHONY: tshark-bin-image
tshark-bin-image:
	docker build dockers/tshark-bin -t meavelabs/tshark_bin:latest


.PHONY: tezos-docker-image
tezos-docker-image:
	docker build tests/tshark-with-ocaml-node -t meavelabs/tezos:v7.3
