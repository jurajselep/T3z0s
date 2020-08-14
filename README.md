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
  dissector-source-root $ make tezos-docker-image
  ```

- Build Rust nightly container:

  ```
  dissector-source-root $ make rust-nightly-docker-image
  ```

- Build container with wireshark/tshark (it takes a long time and container is quite big):

  ```
  dissector-source-root $ make test-docker-image
  ```

- Run combined test: It runs tezos node and tshark node that listens for about 5 minutes for Tezos messages:

  ```
  dissector-source-root $ make test-tshark-with-carthagenet
  ```

  