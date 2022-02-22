# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2022-02-22

### Changed

- secc interface is passed as an argument to SECCHandler by @snorkman88 in https://github.com/SwitchEV/iso15118/pull/17
- Added EVInterface as an argument to the EVCCHandler by @tropxy in https://github.com/SwitchEV/iso15118/pull/18

### Removed

- Removed exi dependency and reformat of the code main files by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/14

## [0.1.0] - 2022-01-04

### Added

- Improved SECC and EVCC configuration handling and updated readme by @tropxy in https://github.com/SwitchEV/iso15118/pull/6
- Github actions workflow and reformat of the code by @tropxy in https://github.com/SwitchEV/iso15118/pull/8

### Changed

- Updated README.md by @MarcMueltin in https://github.com/SwitchEV/iso15118/pull/1
- Simplification of the Authorization process_message method by @tropxy in https://github.com/SwitchEV/iso15118/pull/5

### Removed

- Removed mqtt api as dependency by @tropxy in https://github.com/SwitchEV/iso15118/pull/3

### Fixed

- Fixed compatibility with linux by @tropxy in https://github.com/SwitchEV/iso15118/pull/2
- Fixed 1090 physical types validation error by @tropxy in https://github.com/SwitchEV/iso15118/pull/7
- Fix of the several messages that misused the List type by @tropxy in https://github.com/SwitchEV/iso15118/pull/4

## N/A - 2021-11-20

- Repository transfer from Josev to this one
