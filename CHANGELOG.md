# Changelog

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.23.1] - 2023-08-02
* Updated readme. Removed dc underdevelopment comment by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/272
* chore(deps-dev): bump black from 23.3.0 to 23.7.0 by @dependabot in https://github.com/SwitchEV/iso15118/pull/275
* Make running of udp server optional by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/274
* Feature/test data and fixes by @martinbachmanndesignwerk in https://github.com/SwitchEV/iso15118/pull/276
* JTT-52: Stop charging if state C not detected in PowerDelivery state. by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/282
* chore(deps-dev): bump flake8 from 6.0.0 to 6.1.0 by @dependabot in https://github.com/SwitchEV/iso15118/pull/283
* Simulate precharge ongoing before finished by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/284
* Simulate welding detection ongoing before finished by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/285
* Return FAILED_CertificateExpired is certificate is not yet valid by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/286

## [0.23.0] - 2023-06-30
* chore(deps-dev): bump mypy from 1.2.0 to 1.3.0 by @dependabot in https://github.com/SwitchEV/iso15118/pull/250
* chore(deps): bump cryptography from 40.0.1 to 41.0.1 by @dependabot in https://github.com/SwitchEV/iso15118/pull/251
* chore(deps-dev): bump pytest-cov from 3.0.0 to 4.1.0 by @dependabot in https://github.com/SwitchEV/iso15118/pull/253
* chore(deps-dev): bump pytest from 7.2.2 to 7.3.2 by @dependabot in https://github.com/SwitchEV/iso15118/pull/254
* chore(deps-dev): bump black from 22.3.0 to 23.3.0 by @dependabot in https://github.com/SwitchEV/iso15118/pull/260
* chore(deps-dev): bump mypy from 1.3.0 to 1.4.0 by @dependabot in https://github.com/SwitchEV/iso15118/pull/261
* Add missing optional fileds in CurrentDemandRes DIN70121 by @sdrabb in https://github.com/SwitchEV/iso15118/pull/259
* Fix min_length of EVSE ID for DIN protocol by @adoebber in https://github.com/SwitchEV/iso15118/pull/257
* chore(deps-dev): bump pytest from 7.3.2 to 7.4.0 by @dependabot in https://github.com/SwitchEV/iso15118/pull/263
* AB#5144:support to return certificate validation status. by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/265
* Python gc by @ikaratass in https://github.com/SwitchEV/iso15118/pull/266

## [0.22.0] - 2023-06-16
* feat: add dependabot GHA by @mdwcrft in https://github.com/SwitchEV/iso15118/pull/224
* chore(deps): bump actions/setup-python from 2 to 4 by @dependabot in https://github.com/SwitchEV/iso15118/pull/246
* chore(deps-dev): bump pytest-asyncio from 0.18.3 to 0.21.0 by @dependabot in https://github.com/SwitchEV/iso15118/pull/247
* chore(deps-dev): bump flake8 from 4.0.1 to 6.0.0 by @dependabot in https://github.com/SwitchEV/iso15118/pull/248
* Fix/terminate status by @ikaratass in https://github.com/SwitchEV/iso15118/pull/245
* AB#5093 Skip SalesTariff if free service. by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/249

## [0.21.2] - 2023-06-14
* Fix: iso20 SessionStopReq incorrect payload type 0x8001 by @aadritG in https://github.com/SwitchEV/iso15118/pull/228
* terminate java gateway on exit by @rstanchak in https://github.com/SwitchEV/iso15118/pull/231
* Fix tls_no_tls_switching_issue. by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/237
* Support pause/wakeup in 15118-2 by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/198
* AB#4965 : Fixed dummy schedule generation by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/241
* imp/state info by @ikaratass in https://github.com/SwitchEV/iso15118/pull/243

## [0.21.2a2] - 2023-05-11
* Specify purpose when creating ssl context.

## [0.21.2a1] - 2023-05-11
* Removed sales tariff from the returned simulated schedule.

## [0.21.2a0] - 2023-05-11
* Temp fix for tcp/tls switching issue.

## [0.21.1] - 2023-05-10
* Updated cryptography to 40.0.1 by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/234

## [0.21.0] - 2023-04-26
* is_ready_to_charge control added for Authorization by @ikaratass in https://github.com/SwitchEV/iso15118/pull/227

## [0.20.0] - 2023-03-22

### Fixed
* ConnectionResetError has been added for receive by @ikaratass in https://github.com/SwitchEV/iso15118/pull/214

### Added
* debug message added for cretificateintallationres by @ikaratass in https://github.com/SwitchEV/iso15118/pull/210

## [0.19.0] - 2023-03-09

### Added
* Report of the evse status during the charging loop of both AC and DC in -20 by @tropxy in https://github.com/SwitchEV/iso15118/pull/207
* saved selected protocol in evse controller interface by @tropxy in https://github.com/SwitchEV/iso15118/pull/208

## [0.18.0] - 2023-03-07

### Changed
* Support to report the charging power limits during the charging loop by @tropxy in https://github.com/SwitchEV/iso15118/pull/204
* Handle "Ongoing"  from EVSE during authorization. by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/205

## [0.17.0] - 2023-03-01

### Changed
* Start TCP server after an SDP request is received. by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/199
* AB#4208 Not detecting C/D shouldn't stop charging session. by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/201

## [0.16.0] - 2023-01-27

### Fixed
* AB#3740: Removed check in SalesTariff validator by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/188
* Fix for UDP server failing to start on Linux VM by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/187
* AB#3669 Inverted cable check contactor status check order by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/186
* Update datatypes.py - fixed range for ChargingProfileEntryMaxPower by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/185
* Fix: SessionSetupReq in -20 had the wrong V2GTP type by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/183
* Feat/update docker config by @santiagosalamandri in https://github.com/SwitchEV/iso15118/pull/195

### Changed
* env variables are moved to json config file by @ikaratass in https://github.com/SwitchEV/iso15118/pull/172
* fix: bump cryptography to v39.0.0 by @snorkman88 in https://github.com/SwitchEV/iso15118/pull/189
* the name of is_external_authorization method has changed to is_eim_au… by @ikaratass in https://github.com/SwitchEV/iso15118/pull/191

## [0.15.0] - 2022-12-20

### Fixed
* fix: changed the link to the switch blog page on ISO 15118-20 by @tropxy in https://github.com/SwitchEV/iso15118/pull/175
* feat: remove argument from UDP server by @snorkman88 in https://github.com/SwitchEV/iso15118/pull/178

### Changed
* Feat/log secc settings by @santiagosalamandri in https://github.com/SwitchEV/iso15118/pull/176

### Added
* Support 15118-20 DC BPT by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/169

## [0.14.2] - 2022-12-05

### Changed
* chore: bump cryptography to 38.0.4 by @mdwcrft in https://github.com/SwitchEV/iso15118/pull/173

## [0.14.1] - 2022-11-28

### Fixed
* Bugfix - Binding the port to the socket does not work (Linux) by @SebaLukas in https://github.com/SwitchEV/iso15118/pull/168

### New Contributors
* @SebaLukas made their first contribution in https://github.com/SwitchEV/iso15118/pull/168


## [0.14.0] - 2022-11-22

### Fixed
* feat: run code qual and tests in gha by @mdwcrft in https://github.com/SwitchEV/iso15118/pull/147
* fix: use utcnow() to check certificate validity by @rstanchak in https://github.com/SwitchEV/iso15118/pull/151
* fix: cleanup template dockerfile by @mdwcrft in https://github.com/SwitchEV/iso15118/pull/109
* Fix/genchallange invalid by @ikaratass in https://github.com/SwitchEV/iso15118/pull/154
* Fix/set present by @ikaratass in https://github.com/SwitchEV/iso15118/pull/159
* Fix: UDP server bind issue after PR#161 by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/164
* Fix:service detail res by @ikaratass in https://github.com/SwitchEV/iso15118/pull/144
* genchallange check has been added for Authorization by @ikaratass in https://github.com/SwitchEV/iso15118/pull/135
* Fix tc secc ac vtb power delivery 010 by @ikaratass in https://github.com/SwitchEV/iso15118/pull/150

### Changed
* Update udp socket to bind to specific interface by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/161
* feat: interface added for pause and terminate by @ikaratass in https://github.com/SwitchEV/iso15118/pull/155
* Minor logging improvement. by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/162
* Feat/external auth by @ikaratass in https://github.com/SwitchEV/iso15118/pull/163

### New Contributors
* @rstanchak made their first contribution in https://github.com/SwitchEV/iso15118/pull/151

## [0.13.0] - 2022-10-17

### Fixed

* Fix/serviceDiscoveryreq is not allowed after receiving first one by @ikaratass in https://github.com/SwitchEV/iso15118/pull/143
* fix: remove sphinx dependency by @mdwcrft in https://github.com/SwitchEV/iso15118/pull/141
* Fix: create_certs to generate jks certs for Keysight by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/134
### Added

* feat: Add Service status in https://github.com/SwitchEV/iso15118/pull/148
* get from the evse controller the ac evse status by @tropxy in https://github.com/SwitchEV/iso15118/pull/146

## [0.12.0] - 2022-10-03

### Changed
- Feature/add protocol state to interface by @lukaslombriserdesignwerk in https://github.com/SwitchEV/iso15118/pull/136
- Feat/improve logging/ab#2898 by @santiagosalamandri in https://github.com/SwitchEV/iso15118/pull/139
Thank you @santiagosalamandri for your first contribution :)

## [0.11.0] - 2022-09-22

### Added
- Exception handling for reading mo cert by @ikaratass in https://github.com/SwitchEV/iso15118/pull/133
- Feature/iso din bringup on comemso by @martinbachmanndesignwerk in https://github.com/SwitchEV/iso15118/pull/86
Thank you @martinbachmanndesignwerk for your first contribution ;)

### Changed
- Improvement: Add get_cp_state method to iso15118 interface controller and include cp_status handler by @ikaratass in https://github.com/SwitchEV/iso15118/pull/77
- bumped crypto version to 38.0.1 by @tropxy in https://github.com/SwitchEV/iso15118/pull/137

## [0.10.3] - 2022-09-10

### Added
-added version info to the logs by @tropxy in https://github.com/SwitchEV/iso15118/pull/130

## [0.10.2] - 2022-09-8

### Fixed
- End current session if can't resume by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/128


## [0.10.1] - 2022-09-6

### Changed
- Reverted min Python version to 3.9 in pyproject.toml


## [0.10.0] - 2022-09-2

### Fixed

- fixed the data type expected in EVChargeParamsLimits by @tropxy in https://github.com/SwitchEV/iso15118/pull/118
- Fix/ocsp extraction error raised by @tropxy in https://github.com/SwitchEV/iso15118/pull/120
- exception added for close TCP connection by @ikaratass in https://github.com/SwitchEV/iso15118/pull/121

### Changed

- feat: update python to 3.10 in pyproject toml by @mdwcrft in https://github.com/SwitchEV/iso15118/pull/111
- feat: add make test command by @mdwcrft in https://github.com/SwitchEV/iso15118/pull/110

### Added

- Imp/get contactor state by @ikaratass in https://github.com/SwitchEV/iso15118/pull/123

## [0.9.0] - 2022-08-26

### Fixed

- Empty string field causes EXI encoding error by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/106
- fix: wrong message parameters will return FAILED_WRONG_CHARGE_PARAMETER by @ikaratass in https://github.com/SwitchEV/iso15118/pull/87

### Added

- Feat/complete pnc auth by @tropxy in https://github.com/SwitchEV/iso15118/pull/107
- feat: Enable TLS 1.3 with mutual auth (AB:2378) by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/115
- Log MO cert details to help with debugging. by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/116

## [0.8.1] - 2022-08-08

### Fixed

- ChargeParameterDiscoveryRes must be ac_charge_parameter and not ac_ev… by @ikaratass in https://github.com/SwitchEV/iso15118/pull/99
- Added more EXI debug (AB#2580) by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/100

## [0.8.0] - 2022-08-05

### Added

- makefile comments and cleanup
- Add option to fetch CertificateInstallationRes
- Update create_certs.sh to help testing with Keysight
- support multiple passwords for private keys (AB#2546)
- plug and charge authorization, basic happy path

### Fixed

- EXI grammar violation for failed response.
- MessageProcessingError.init() missing 1 required positional argument: 'message_name'
- missing parameters are added for ChargeParameterDiscoveryRes and PowerDeliveryRes

## [0.7.3] - 2022-07-15

### Fixed

- Includes fixes for issues identified at the CharIN Testival July 2022 (signature verification issue in CertificateInstallation state with CertificateInstallationReq)

### Removed

- Removed unused EXICodec.jar.bkp file

## [0.7.2] - 2022-06-24

### Added

- created a new env CERTS_GENERAL_PRIVATE_KEY_PASS_PATH to be able to d… by @tropxy in https://github.com/SwitchEV/iso15118/pull/71

## [0.7.1] - 2022-06-22

### Changed

- feat: set hlc charging before closing contactor by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/67
- Updated version_number by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/68

## [0.7.0] - 2022-06-20

### Added

- CS contactor by @ikaratass in https://github.com/SwitchEV/iso15118/pull/63

### Removed

- removed unused functions and tasks from utils.py; added reference links by @tropxy in https://github.com/SwitchEV/iso15118/pull/64

### Fixed

- fixed order of closing contactor and reformated the code by @tropxy in https://github.com/SwitchEV/iso15118/pull/65

## [0.6.0] - 2022-06-16

### Added

- Make communication protocols configurable via .env file by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/60

### Fixed

- Schedule entry durations in ChargeParameterDiscoveryRes should add up to departure_time from EVCC (AB#2183) by @shalinnijel2 in https://github.com/SwitchEV/iso15118/pull/59

### Changed

- docs: fix formatting issues by @danielgordon-switch-ev in https://github.com/SwitchEV/iso15118/pull/53
- fixed some technical terms in the readme by @tropxy in https://github.com/SwitchEV/iso15118/pull/50
- converted all process_messages instances to async by @tropxy in https://github.com/SwitchEV/iso15118/pull/61
- authorization state enum by @danielgordon-switch-ev in https://github.com/SwitchEV/iso15118/pull/52

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
