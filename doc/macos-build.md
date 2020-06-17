macOS Build
==========

- Not working yet. :-(

        $ brew install cmake ninja
        $ brew install c-ares
        $ export Qt5Core_DIR=/opt/Qt/5.14.2/clang_64/
        $ mkdir build
        $ cd build
        $ cmake -G Ninja ..
