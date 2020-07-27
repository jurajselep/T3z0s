SHELL:=/bin/bash

MK_PATH:=$(abspath $(dir $(lastword $(MAKEFILE_LIST))))
T3Z0S_PATH:=${MK_PATH}
WIRESHARK_PATH:=${MK_PATH}/wireshark
WIRESHARK_OPT_PATH:=${MK_PATH}/opt
WIRESHARK_BIN_PATH:=${WIRESHARK_OPT_PATH}/bin

############################################################
# Preparation steps, must be called as root :-(

.PHONY: clone-wireshark
clone-wireshark:
	if [ ! -d "${WIRESHARK_PATH}" ]; then \
		git clone https://github.com/wireshark/wireshark.git "${WIRESHARK_PATH}" && \
		cd "${WIRESHARK_PATH}" && \
		git checkout b99a0c95d8c3fec834da0b7be27b2fc385054646; \
	fi

.PHONY: patch-wireshark
patch-wireshark:
	cd "${WIRESHARK_PATH}" && if ! grep t3z0s CMakeLists.txt >/dev/null 2>/dev/null; then patch -p1 <"${T3Z0S_PATH}/wireshark.diff"; fi

.PHONY: symlink-for-wireshark
symlink-for-wireshark:
	cd "${WIRESHARK_PATH}" && cd plugins/epan && ln -fs "${T3Z0S_PATH}" t3z0s

.PHONY: call-bindgen
call-bindgen:
	cargo install bindgen
	rustup component add rustfmt
	cd "${WIRESHARK_PATH}" && rm -fv "${T3Z0S_PATH}/t3z0s_rs/src/wireshark/packet.rs" && bindgen --no-rustfmt-bindings "epan/packet.h" -o "${T3Z0S_PATH}/t3z0s_rs/src/wireshark/packet.rs" -- -I. $(shell pkg-config --cflags glib-2.0)
	cd "${WIRESHARK_PATH}" && rustfmt "${T3Z0S_PATH}/t3z0s_rs/src/wireshark/packet.rs"

.PHONY: prepare
prepare: clone-wireshark patch-wireshark symlink-for-wireshark call-bindgen

############################################################
# Main part, building

.PHONY: build-t3z0s
build-t3z0s: call-bindgen
	cd "${T3Z0S_PATH}/t3z0s_rs" && cargo build

.PHONY: symlink-of-lib
symlink-of-lib:
	mkdir -p "${WIRESHARK_PATH}/build/run" && cd "${WIRESHARK_PATH}/build/run" && ln -fs "${T3Z0S_PATH}/t3z0s_rs/target/debug/libt3z0s_rs.a" .

.PHONY: build-wireshark
build-wireshark: symlink-of-lib
	cd "${WIRESHARK_PATH}" && mkdir -p build && cd build && cmake .. -DCMAKE_INSTALL_PREFIX="${WIRESHARK_OPT_PATH}" && make

.PHONY: build
build: build-t3z0s build-wireshark

############################################################
# installing

.PHONY: install
install: build
	cd "${WIRESHARK_PATH}" && cd build && make install

.PHONY: sbit-for-dumpcat
sbit-for-dumpcat:
	cd "${WIRESHARK_BIN_PATH}" && chown root.root dumpcap && chmod u+s dumpcap

############################################################
# cleaning

.PHONY: clean-t3z0s
clean-t3z0s:
	rm -fv "${WIRESHARK_PATH}/run/plugins/3.3/epan/t3z0s.so"

.PHONY: clean
clean: clean-t3z0s
	cd "${T3Z0S_PATH}/t3z0s_rs" && cargo clean
	if [ -e "${WIRESHARK_PATH}/build" ]; then cd "${WIRESHARK_PATH}/build" && make clean; fi

.PHONY: mrproper
mrproper: clean
	rm -vfr "${WIRESHARK_PATH}/build"

############################################################
# tests

.PHONY: clone-tezedge-debugger
clone-tezedge-debugger:
	if [ ! -d  tezedge-debugger ]; then \
		git clone https://github.com/simplestaking/tezedge-debugger.git && \
		cd tezedge-debugger && \
		git checkout 8209f6b834ee89bb0f9ed35d2da61d66f4b593ea; \
	fi

.PHONY: prepare-for-test
prepare-for-test: clone-tezedge-debugger
	cd tezedge-debugger && cargo install --bins --path . --root .

.PHONY: test-tshark-over-pcap
test-tshark-over-pcap:
	tests/tools/tshark-over-pcap.sh

.PHONY: test-srv-cli-tshark
test-srv-cli-tshark:
	tests/tools/srv-cli-tshark.sh

.PHONY: test
test: test-tshark-over-pcap test-srv-cli-tshark


.bin/carthagenet.sh:
	mkdir -p .bin
	wget -O .bin/carthagenet.sh https://gitlab.com/tezos/tezos/raw/latest-release/scripts/tezos-docker-manager.sh
	chmod u+x .bin/carthagenet.sh

.PHONY: check-docker-test-image
check-docker-test-image:
	if ! grep 't3z0s[/]test:latest' <(docker images --format '{{.Repository}}:{{.Tag}}'); then \
		${MAKE} test-docker-image; \
	fi


.PHONY: test-tshark-with-carthagenet
test-tshark-with-carthagenet: .bin/carthagenet.sh check-docker-test-image
	docker rm -f test_tshark_with_carthagenet || true
	.bin/carthagenet.sh stop || true

	.bin/carthagenet.sh start
	mkdir -p .tmp
	while ! docker cp carthagenet_node_1:/var/run/tezos/node/data/identity.json .tmp; do sleep 1; done
	while ! docker cp .tmp/identity.json test_tshark_with_carthagenet:/tmp; do sleep 1; done &

	docker run \
		--name test_tshark_with_carthagenet \
		-u appuser \
		--network container:carthagenet_node_1 \
		t3z0s/test:latest \
		/home/appuser/tests/tools/listen-to-tezos-node.sh

	.bin/carthagenet.sh stop


############################################################
# docker-images
.PHONY: test-docker-image
test-docker-image: clone-wireshark clone-tezedge-debugger
	docker build . -t t3z0s/test
