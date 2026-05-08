# sqlite3-amalgamation
this repository contains a cmake based build of sqlite (and its tools) based on source download from sqlite.org

## SCADAPack VxWorks crypto build

Build the VxWorks crypto package into a platform-specific prefix:

```bash
cmake -S . -B build/scadapack-vxworks \
  -DCMAKE_TOOLCHAIN_FILE=/path/to/ScadaPack350Toolchain.cmake \
  -DCMAKE_BUILD_TYPE=Release \
  -DSQLITE_ENABLE_VXWORKS=ON \
  -DBUILD_SHELL=OFF \
  -DSCADAPACK_CTOOLS=/path/to/ctools \
  -DCMAKE_INSTALL_PREFIX=/i/ports/install/sqlite3/scadapack-vxworks

cmake --build build/scadapack-vxworks
cmake --install build/scadapack-vxworks
```

The install exports the normal package target `SQLite::SQLite3cry`; the install
prefix identifies the platform.

Required CMake cache settings:

| Option | Value | Purpose |
| --- | --- | --- |
| `CMAKE_TOOLCHAIN_FILE` | SCADAPack ARM/VxWorks toolchain file | Selects `arm-none-eabi-*` tools and VxWorks link settings. |
| `SQLITE_ENABLE_VXWORKS` | `ON` | Builds the SCADAPack VxWorks `SQLite3cry` static archive only. |
| `BUILD_SHELL` | `OFF` | Skips host shell executables that are not part of the firmware package. |
| `SCADAPACK_CTOOLS` | SCADAPack CTools root | Provides VxWorks and TelePACE headers. |
| `CMAKE_INSTALL_PREFIX` | Platform-specific install prefix | Keeps the exported package discoverable without renaming the target. |

The VxWorks target adds SCADAPack CPU/toolchain defines, disables SQLite
threading/loadable extensions, keeps crypto VFS enabled, and exports the normal
`SQLite::SQLite3cry` package target. Firmware builds should consume the install
prefix rather than include files from this source tree.

## TODO
- [ ] integrate build of sqldiff
- [ ] make cleaner build by splitting static and dynamic library build into separate builds (based on ideas of alex reinking)
