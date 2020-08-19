# Tezos Dissector

## Installation from the sources

- Ubuntu 20.04:

  - Install required packages:

    ```
    # apt update && DEBIAN_FRONTEND=noninteractive apt install -y \
    bison \
    build-essential \
    clang \
    cmake \
    curl \
    flex \
    git \
    libc-ares-dev \
    llvm \
    libgcrypt-dev \
    libglib2.0-dev \
    libpcap-dev \
    libsodium-dev \
    libssl-dev \
    pkg-config \
    qtmultimedia5-dev \
    qttools5-dev
    ```

    

  - Install Rust nightly, recommended version is: `2020-07-26`:

    ```
    ~ $ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs >.rust.sh
    ~ $ sh .rust.sh -y && rm -v .rust.sh && source $HOME/.cargo/env
    ~ $ rustup default nightly-2020-07-26 && rustup default nightly-2020-07-26
    ~ $ echo >>.bashrc && echo 'source $HOME/.cargo/env' >>.bashrc
    ```

  - Set environment variables for build of `libsodium` (without this step you will get strange error from linker at the end of the build):

    ```
    $ export SODIUM_SHARED=1
    $ export SODIUM_USE_PKG_CONFIG=1
    ```

  - Download Wireshark sources and prepare for the build:

    ```
    dissector-source-root $ make prepare
    ```

  - Build and install Tezos plugin and Wireshark:

    ```
    dissector-source-root $ make install
    ```

    Wireshark should be installed to `opt` subdirectory of the current directory. You can change the installation destination with `WIRESHARK_OPT_PATH` variable inside `Makefile`.
  
  
  
  ## Running of the wireshark/tshark

Don't forget to configure `idenity` file location to make decryption working. If `wireshark` was installed to the default location -- `opt` subdirectory of the current directory, you can run `tshark` with command:

```
opt/bin/tshark -o tezos.identity_json_file:/path/to/identity.json ...
```

And you can run `wireshark` with command:

```
opt/bin/wireshark
```

and configure path to identity file through menu: `Edit |> Preferences |> Protocols |> tezos`.

## Building of Docker containers and running of multinode test

* Build Tezos node container:

  ```
  dissector-source-root $ docker build tests/tshark-with-ocaml-node -t meavelabs/tezos:v7.3
  ```
  
  * Or you can use `make`:
  
  ```
  dissector-source-root $ make tezos-docker-image
  ```

- Build Rust nightly container:

  ```
  docker build dockers/rust-nightly-20200726 -t meavelabs/rust:nightly-20200726
  ```

  * Or you can use `make`:

  ```
  dissector-source-root $ make rust-nightly-docker-image
  ```

- Build container with wireshark/tshark (it takes a long time and container is quite big):

  ```
  dissector-source-root $ docker build . -t meavelabs/tshark:latest
  ```

  * Or use `make`:

  ```
  dissector-source-root $ make test-docker-image
  ```

- Now you can also build image `meavelabs/tshark_bin:latest` that contains only `tshark` binary and necessary libraries:

  ```
  docker build dockers/tshark-bin -t meavelabs/tshark_bin:latest
  ```

  * Or use `make`:

  ```
  make tshark-bin-image
  ```

- At this moment, you can run combined test: It runs Tezos node and tshark node together. `tshark` listens for about 5 minutes for Tezos messages and then the test checks whether some messages were decrypted:

  ```
  dissector-source-root/tests/tshark-with-ocaml-node $ docker-compose rm --force ; docker-compose up
  ```

  * Again, you can use `make`:

  ```
  dissector-source-root $ make test-tshark-with-carthagenet
  ```

  

  ## Running of tshark docker node together with Tezos node

* You will work in two terminals. In the first terminal, run Tezos node to make sure it generates identity:

```
$ docker run -v ~/node-data:/var/run/tezos/node -u 0 -it tezos/tezos:v7.3 tezos-node --net-addr :19732 --network carthagenet
```

- Stop it after it prints: `node.main: read identity file (peer_id = ...)`.
- Run `tshark` node in another terminal and ask it to load identity from Tezos node:

```
$ docker run -v ~/node-data:/var/run/tezos/node -u 0 -it --name tshark meavelabs/tshark:latest /home/appuser/opt/bin/tshark -o tezos.identity_json_file:/var/run/tezos/node/data/identity.json -i any -V
```

- Image `meavelabs/tshark:latest` is used for development and is quite large. You can use image `meavelabs/tshark_bin:latest` that is much smaller:

```
docker run -v ~/node-data:/var/run/tezos/node -u 0 -it --name tshark meavelabs/tshark_bin:latest /home/appuser/opt/bin/tshark -o tezos.identity_json_file:/var/run/tezos/node/data/identity.json -i any -V
```

- When `tshark` starts to listen to `any`interface, return to previous terminal and run Tezos node again. This time, force it to share network card with `tshark` node:

```
$ docker run -v ~/node-data:/var/run/tezos/node --net container:tshark --name tezos_node -u 0 -it tezos/tezos:v7.3 tezos-node --net-addr :19732 --network carthagenet
```
* You can replace `~/node-data` with different directory, but it must be the same for every command.