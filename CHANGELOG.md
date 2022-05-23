# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2022-05-24

### Added
- docs: add details discovered in running locally by @danielgordon-switch-ev in https://github.com/SwitchEV/iso15118/pull/43
- added the apache license by @tropxy in https://github.com/SwitchEV/iso15118/pull/47

### Fixed
- fixes for the issues found during the vector testival by @tropxy in https://github.com/SwitchEV/iso15118/pull/38
- Fixed error while constructing PaymentDetailsReq message.(AB#1936) by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/41

### Changed
- Updated README. by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/36
- docs: restructure readme by @danielgordon-switch-ev in https://github.com/SwitchEV/iso15118/pull/46
- switch the upload to the public pypi server by @tropxy in https://github.com/SwitchEV/iso15118/pull/48
- chore: use lockfile instead of poetry update by @danielgordon-switch-ev in https://github.com/SwitchEV/iso15118/pull/45


## [0.4.0] - 2022-04-30

### Added

- feat: Support for 15118-20 AC and AC_BPT by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/33
- bumped to version 0.4.0 by @tropxy in https://github.com/SwitchEV/iso15118/pull/34

### Fixed

- fixed: converted debug messages to info by @tropxy in https://github.com/SwitchEV/iso15118/pull/34
- setting of the logger level based on the .env file info by @tropxy in https://github.com/SwitchEV/iso15118/pull/34
- Updated the README with the ability to set MESSAGE_LOG_JSON and MESSAGE_LOG_EXI by @tropxy in https://github.com/SwitchEV/iso15118/pull/34

### Removed

- Removed aioredis dependency as it is not used by @tropxy in https://github.com/SwitchEV/iso15118/pull/34

## [0.3.0] - 2022-04-13

### Added

- DC support was added for 15118-2 by @lukaslombriserdesignwerk in https://github.com/SwitchEV/iso15118/pull/21
- DIN SPEC 70121 was added by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/24

## [0.2.1] - 2022-03-13

### Changed

- fixed get_version arguments and version extraction by @tropxy in https://github.com/SwitchEV/iso15118/pull/22
- downgraded cryptography version @tropxy in https://github.com/SwitchEV/iso15118/pull/23

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
