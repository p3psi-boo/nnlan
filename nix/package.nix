{ lib, rustPlatform }:
rustPlatform.buildRustPackage {
  pname = "nnlan";
  version = "0.1.0";
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../Cargo.toml ../Cargo.lock ../src ../examples ../tests/fixtures
      (lib.fileset.fileFilter (file: file.hasExt "rs") ../tests)
    ];
  };
  cargoLock.lockFile = ../Cargo.lock;
  meta = {
    description = "Decentralized encrypted Linux overlay";
    mainProgram = "nnlan";
    platforms = lib.platforms.linux;
  };
}
