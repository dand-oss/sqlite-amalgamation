# sqlite3-amalgamation
this repository contains a cmake based build of sqlite (and its tools) based on source download from sqlite.org

## SCADAPack VxWorks crypto build

Build the VxWorks crypto package into a platform-specific prefix:

```bash
./build-scadapack-vxworks.sh
```

The install exports the normal package target `SQLite::SQLite3cry`; the install
prefix identifies the platform.

The script defaults to `/i/ports/install/sqlite3/scadapack-vxworks`. Override
the default paths with `SCADAPACK_FIRMWARE_ROOT`, `SCADAPACK_SQLITE_BUILD_DIR`,
`SCADAPACK_SQLITE_PREFIX`, or `SCADAPACK_CTOOLS`.

The VxWorks target adds SCADAPack CPU/toolchain defines, disables SQLite
threading/loadable extensions, keeps crypto VFS enabled, and exports the normal
`SQLite::SQLite3cry` package target. Firmware builds should consume the install
prefix rather than include files from this source tree.

## TODO
- [ ] integrate build of sqldiff
- [ ] make cleaner build by splitting static and dynamic library build into separate builds (based on ideas of alex reinking)
