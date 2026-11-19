# fuzzyhash command-line tool

```
fuzzyhash COMMAND [OPTIONS] [ARGS...]
```

| Command | Prints |
|---|---|
| `ssdeep` | ssdeep digests in the ssdeep 1.1 signature file format, or matches against known signatures |
| `tlsh` | TLSH digests, one `digest<TAB>path` line per file |
| `imphash` | import hashes of PE files |
| `telfhash` | symbol hashes of ELF files |
| `lzjd` | LZJD digests |
| `nilsimsa` | Nilsimsa digests |
| `compare` | the score or distance of two digests |

`fuzzyhash COMMAND --help` lists the options of each command. With no path, or with the path `-`, a command reads standard input. Files are read in 64 KiB chunks; ssdeep, TLSH and Nilsimsa use constant memory for any file size. imphash, telfhash and LZJD read the whole file.

Image hashes, MinHash and SimHash are not in the CLI: they take decoded pixels or token sets, not files. Use the Zig module or the npm package for them.

Exit status: 0 on success, 1 if an input could not be read or hashed, 2 for a usage error.

`--json` on any command prints one JSON object per line instead. Paths that are not valid UTF-8 are written with U+FFFD in place of each invalid byte.

## ssdeep

```
fuzzyhash ssdeep [-r] [-l|-b] [-cs] [--json] [--follow] [PATH...]
fuzzyhash ssdeep -m KNOWN [-m KNOWN...] [-a] [-t N] [-r] [-l|-b] [-cs] [PATH...]
fuzzyhash ssdeep -k KNOWN [-a] [-t N] [-c] SIGFILE...
fuzzyhash ssdeep -x [-a] [-t N] [-c] SIGFILE...
```

Standard output is byte-identical to the `ssdeep` 2.14.1 program run with the same options, in hash mode and in the matching modes. This covers:

- The header line, printed before the first digest, and `digest,"path"` lines with `"` in names written as `\"`. Other bytes in names are written as they are.
- Paths: absolute by default, made from the working directory and the path as given, with `.` and `..` resolved as text (not through symbolic links) and repeated separators collapsed. `-l` keeps paths as given; in a directory walk it adds a separator and the name, so `sub/` gives `sub//file`. `-b` prints the last component only. `-l` and `-b` cannot be combined.
- `-r` lists directories in the order the file system returns them and walks each subdirectory as soon as it is listed.
- Standard input is named `stdin`.
- `-m` prints `PATH matches KNOWN:NAME (SCORE)`, `-k` prints `SIGFILE:NAME matches KNOWN:NAME (SCORE)`, `-x` prints the same for every pair of signatures in the SIGFILEs, with an empty line after each signature that had a match. `-c` prints `"PATH","NAME",SCORE` instead. A match is printed when its score is above `-t` (default 0), or always with `-a`.

Differences from `ssdeep`, all outside standard output in normal use:

- Messages go to standard error with a `fuzzyhash:` prefix and their own wording. When no `-m` file can be loaded, `ssdeep` prints "No matching files loaded" on standard output; `fuzzyhash` prints its message on standard error.
- The exit status is 1 when an input cannot be read, where `ssdeep` exits with 0.
- In a `-r` walk, a symbolic link whose target is outside the tree given on the command line is not followed, and a note is printed on standard error. `--follow` follows it, as `ssdeep` does. Links that stay inside the tree are followed, and a link back to a directory that is being walked is reported as a cycle and not entered, as in `ssdeep`.
- Devices, pipes and sockets inside a `-r` tree are skipped. `ssdeep` opens them and can block on a pipe.
- `-d`, `-p`, `-g` and `-v` are not supported.

`--json` prints `{"family":"ssdeep","path":...,"digest":...}` per file, and for matches `{"family":"ssdeep","path":...,"match":...,"match_source":...,"score":...}` (with `path_source` for `-k` and `-x`).

## tlsh

```
fuzzyhash tlsh [-r] [--conservative] [--old] [--variant V] [--json] [PATH...]
```

Prints `digest<TAB>path`. Digests are those of TLSH 5.0.2 (`tlsh_unittest -f`). A file that has no digest, because it is shorter than 50 bytes (256 with `--conservative`) or has too little variation, is reported on standard error and listed as `TNULL`; this is not an error. `--old` leaves out the `T1` prefix. `--variant` selects the build: `128-1` (default), `128-3`, `256-1` or `256-3`.

## imphash, telfhash, nilsimsa

```
fuzzyhash imphash [-r] [--json] [PATH...]
fuzzyhash telfhash [-r] [--json] [PATH...]
fuzzyhash nilsimsa [-r] [--json] [PATH...]
```

Print `digest<TAB>path`. imphash gives the same digest as pefile's `get_imphash()` and prints `-` for a PE file without imports. telfhash gives the same text as telfhash 0.9.8, including `tnull` and `-`. A file that pefile or telfhash cannot read is reported on standard error and fails the run. In `--json` output, `digest` is null where the plain output shows `-` or `tnull`.

## lzjd

```
fuzzyhash lzjd [-r] [--hash-size N] [--json] [PATH...]
```

Prints `digest<TAB>path`, where the digest is `lzjd:` followed by the standard base64 (with padding) of its values as little-endian 32-bit integers, in ascending order. The values are those of pyLZJD's `digest` with `hash_size` N (default 1024). This text form belongs to fuzzyhash-ng.

## compare

```
fuzzyhash compare [--xlen] [--json] DIGEST DIGEST
```

Detects the kind of the two digests from their text and prints:

| Kind | Result |
|---|---|
| ssdeep (`blocksize:part1:part2`) | score from 0 to 100, as ssdeep computes it |
| TLSH, any variant, with or without `T1`; telfhash | distance, 0 for identical digests; `--xlen` leaves out the length term |
| Nilsimsa (64 hex digits) | score from -128 to 128 (identical) |
| LZJD (`lzjd:...`) | similarity from 0 to 1 |

Two digests of different kinds, or a text that is not a valid digest, fail with exit status 1.

## Release binaries

`zig build dist` builds the tool with ReleaseSafe for x86_64 and aarch64 Linux (static, musl), x86_64 and aarch64 macOS and x86_64 Windows, into `zig-out/dist/<target>/`. `scripts/package-cli.sh VERSION OUT_DIR` packs each one with `README.md`, `LICENSE` and `LICENSES/` as `fuzzyhash-VERSION-<target>.tar.gz` (`.zip` for Windows) and writes `SHA256SUMS`. The release workflow attaches these to each GitHub Release.
