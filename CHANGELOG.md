## [1.5.13](https://github.com/xarlord/btsec-testtool/compare/v1.5.12...v1.5.13) (2026-06-06)


### Bug Fixes

* **#201,#207:** wire VulnerabilityTestEngine into scanner + real audit log export ([#218](https://github.com/xarlord/btsec-testtool/issues/218)) ([72a08a1](https://github.com/xarlord/btsec-testtool/commit/72a08a1a3ea98a214a0ff9256809a3b15a92d91e)), closes [#201](https://github.com/xarlord/btsec-testtool/issues/201) [#207](https://github.com/xarlord/btsec-testtool/issues/207) [#201](https://github.com/xarlord/btsec-testtool/issues/201) [#207](https://github.com/xarlord/btsec-testtool/issues/207)

## [1.5.12](https://github.com/xarlord/btsec-testtool/compare/v1.5.11...v1.5.12) (2026-06-06)


### Bug Fixes

* **#205:** pass real scanned device to fuzzer/vuln/key-extraction screens ([#217](https://github.com/xarlord/btsec-testtool/issues/217)) ([426b1b9](https://github.com/xarlord/btsec-testtool/commit/426b1b9de1ca054acc599d20225b5f9cdffc209c)), closes [#205](https://github.com/xarlord/btsec-testtool/issues/205)

## [1.5.11](https://github.com/xarlord/btsec-testtool/compare/v1.5.10...v1.5.11) (2026-06-06)


### Bug Fixes

* **#199,#200,#203,#213,#214:** wire real engines into repositories — replace stubs with working implementations ([#216](https://github.com/xarlord/btsec-testtool/issues/216)) ([73802da](https://github.com/xarlord/btsec-testtool/commit/73802daa9b12545993ecb71b1f4298e6ff133193)), closes [#199](https://github.com/xarlord/btsec-testtool/issues/199) [#200](https://github.com/xarlord/btsec-testtool/issues/200) [#203](https://github.com/xarlord/btsec-testtool/issues/203) [#213](https://github.com/xarlord/btsec-testtool/issues/213) [#214](https://github.com/xarlord/btsec-testtool/issues/214) [#199](https://github.com/xarlord/btsec-testtool/issues/199) [#200](https://github.com/xarlord/btsec-testtool/issues/200) [#203](https://github.com/xarlord/btsec-testtool/issues/203) [#213](https://github.com/xarlord/btsec-testtool/issues/213) [#214](https://github.com/xarlord/btsec-testtool/issues/214)

## [1.5.10](https://github.com/xarlord/btsec-testtool/compare/v1.5.9...v1.5.10) (2026-06-06)


### Bug Fixes

* **test:** add Dispatchers.Main setup to ViewModel tests - 30 to 0 failures ([#193](https://github.com/xarlord/btsec-testtool/issues/193)) ([f94fe39](https://github.com/xarlord/btsec-testtool/commit/f94fe39dd488b4a8578c83d47df99911c19d2a3c)), closes [#171](https://github.com/xarlord/btsec-testtool/issues/171) [#172](https://github.com/xarlord/btsec-testtool/issues/172)

## [1.5.9](https://github.com/xarlord/btsec-testtool/compare/v1.5.8...v1.5.9) (2026-06-06)


### Bug Fixes

* **quality:** extract string resources, begin UI decomposition ([#184](https://github.com/xarlord/btsec-testtool/issues/184)) ([d5a9751](https://github.com/xarlord/btsec-testtool/commit/d5a9751391d7d058bc7de6fc387ff6780186c7d2)), closes [#133](https://github.com/xarlord/btsec-testtool/issues/133) [#129](https://github.com/xarlord/btsec-testtool/issues/129) [#125](https://github.com/xarlord/btsec-testtool/issues/125)

## [1.5.8](https://github.com/xarlord/btsec-testtool/compare/v1.5.7...v1.5.8) (2026-06-06)


### Bug Fixes

* **ui:** add loading/empty/error states and accessibility content descriptions ([#182](https://github.com/xarlord/btsec-testtool/issues/182)) ([9ff3428](https://github.com/xarlord/btsec-testtool/commit/9ff3428b113f41c9144d9ae224c47ca46f4c0d90)), closes [#135](https://github.com/xarlord/btsec-testtool/issues/135) [#134](https://github.com/xarlord/btsec-testtool/issues/134)

## [1.5.7](https://github.com/xarlord/btsec-testtool/compare/v1.5.6...v1.5.7) (2026-06-06)


### Bug Fixes

* **ble:** implement readCharacteristic, subscribeToCharacteristic, readDescriptor ([#181](https://github.com/xarlord/btsec-testtool/issues/181)) ([6322c22](https://github.com/xarlord/btsec-testtool/commit/6322c2296b744983a9ef281d57b9ee5f8557faf4)), closes [#131](https://github.com/xarlord/btsec-testtool/issues/131)

## [1.5.6](https://github.com/xarlord/btsec-testtool/compare/v1.5.5...v1.5.6) (2026-06-06)


### Bug Fixes

* **persistence:** wire Room DAOs into consent, report, and bluetooth repositories ([#180](https://github.com/xarlord/btsec-testtool/issues/180)) ([89af74c](https://github.com/xarlord/btsec-testtool/commit/89af74c4bf87efa3d3a90c24ec1c9efe1a56d0b8))

## [1.5.5](https://github.com/xarlord/btsec-testtool/compare/v1.5.4...v1.5.5) (2026-06-06)


### Bug Fixes

* resolve test compilation errors, add kotlin-test dependency, fix AuthorizationBackend HTTPS enforcement ([30cc487](https://github.com/xarlord/btsec-testtool/commit/30cc48786d3444a153e7dd3988dfb524fbf3b02b))

## [1.5.4](https://github.com/xarlord/btsec-testtool/compare/v1.5.3...v1.5.4) (2026-06-06)


### Bug Fixes

* **security:** validate BT service intents, require explicit consent, add server verification ([#179](https://github.com/xarlord/btsec-testtool/issues/179)) ([1e655cb](https://github.com/xarlord/btsec-testtool/commit/1e655cb3a55a2fbb49130075b542849770652973)), closes [#153](https://github.com/xarlord/btsec-testtool/issues/153) [#152](https://github.com/xarlord/btsec-testtool/issues/152) [#126](https://github.com/xarlord/btsec-testtool/issues/126)

## [1.5.3](https://github.com/xarlord/btsec-testtool/compare/v1.5.2...v1.5.3) (2026-06-06)


### Bug Fixes

* security, code quality, and accessibility improvements ([31d80b3](https://github.com/xarlord/btsec-testtool/commit/31d80b329d16b51b8c554c12e72b672ae0de83a6))

## [1.5.2](https://github.com/xarlord/btsec-testtool/compare/v1.5.1...v1.5.2) (2026-06-06)


### Bug Fixes

* resolve review findings - manifest, mapper logging, fuzz tests ([#141](https://github.com/xarlord/btsec-testtool/issues/141)) ([96c593a](https://github.com/xarlord/btsec-testtool/commit/96c593a372f390a4f99a524408b93e99629ae8f9)), closes [#128](https://github.com/xarlord/btsec-testtool/issues/128) [#130](https://github.com/xarlord/btsec-testtool/issues/130) [#139](https://github.com/xarlord/btsec-testtool/issues/139)

## [1.5.1](https://github.com/xarlord/btsec-testtool/compare/v1.5.0...v1.5.1) (2026-06-05)


### Bug Fixes

* resolve all compilation errors across 8 implementation phases ([e5910cb](https://github.com/xarlord/btsec-testtool/commit/e5910cbbc5e7e89329f7bc35d8dfd36f4c4aeb7f))

# [1.5.0](https://github.com/xarlord/btsec-testtool/compare/v1.4.0...v1.5.0) (2026-06-05)


### Features

* authorization backend, settings screen, error handling, BT state monitor ([98da201](https://github.com/xarlord/btsec-testtool/commit/98da20105464fbfd4a584cb7ff91ed11bcd5b488))

# [1.4.0](https://github.com/xarlord/btsec-testtool/compare/v1.3.0...v1.4.0) (2026-06-05)


### Features

* implement fuzzing engine, vulnerability tests, and report generation ([476e026](https://github.com/xarlord/btsec-testtool/commit/476e026eed0184a8b83da39b21ed2092df75e5aa))

# [1.3.0](https://github.com/xarlord/btsec-testtool/compare/v1.2.1...v1.3.0) (2026-06-05)


### Features

* implement real application infrastructure ([c5fe984](https://github.com/xarlord/btsec-testtool/commit/c5fe984a7a530ee8216730c812772fc8a87f68ac))

## [1.2.1](https://github.com/xarlord/btsec-testtool/compare/v1.2.0...v1.2.1) (2026-06-05)


### Bug Fixes

* resolve compilation blockers and security issues ([0fee715](https://github.com/xarlord/btsec-testtool/commit/0fee71566cb6c46e9ab6eb44eba5ea8b60c655b3))

# [1.2.0](https://github.com/xarlord/btsec-testtool/compare/v1.1.4...v1.2.0) (2026-04-17)


### Bug Fixes

* Correct AndroidX Hilt compiler version ([99d0ae0](https://github.com/xarlord/btsec-testtool/commit/99d0ae0665ee28d26d4c9dc7df69179804c0af8c))
* correct Jenkinsfile comment syntax (# to //) ([3d1c16e](https://github.com/xarlord/btsec-testtool/commit/3d1c16ebc6feef280ec98c87cfff36a5a49891ab))
* improve ktlint download for Git Bash on Windows ([92a0a69](https://github.com/xarlord/btsec-testtool/commit/92a0a69e4978eeaea8bfe3b9a77e6fceee740629))
* improve pipeline completion detection ([2b15fa5](https://github.com/xarlord/btsec-testtool/commit/2b15fa57e4d9b97bc74a10ca36f8c895b158a135))
* resolve all Kotlin compilation errors and build issues ([47a699c](https://github.com/xarlord/btsec-testtool/commit/47a699ce791a4e98784b19b8dbccfc93a97361eb))
* resolve Android resource and manifest merger issues ([85ae0d8](https://github.com/xarlord/btsec-testtool/commit/85ae0d878c736928d1a3c598ace4283d8a8ff538))
* resolve DI configuration issues and Compose compiler compatibility ([ea8fd53](https://github.com/xarlord/btsec-testtool/commit/ea8fd5358fb009248d2e040c88159d78980711ca))
* resolve project build and compilation issues ([7fe243e](https://github.com/xarlord/btsec-testtool/commit/7fe243ec80a9fb533218852dd11dfa9b9be36e96))
* restore working .woodpecker.yml configuration ([76a45b2](https://github.com/xarlord/btsec-testtool/commit/76a45b2296c1704746816568c880c2e4f06aa480))
* update Jenkinsfile agent labels to match actual agent labels ([55cc1ae](https://github.com/xarlord/btsec-testtool/commit/55cc1aed0c8ad48aee15b9229db3190aef8a04ad))


### Features

* add autonomous CI/CD monitoring and auto-fix system ([eddb7ff](https://github.com/xarlord/btsec-testtool/commit/eddb7fffb193979a4a89cf875a68917c4fe39924)), closes [#17](https://github.com/xarlord/btsec-testtool/issues/17)
* add comprehensive UI testing suite and fix authorization window validation ([1de765c](https://github.com/xarlord/btsec-testtool/commit/1de765c6ce5b2230fa34d4fd3f719c4ce127c68b))
* add local CI/CD scripts ([c533aa5](https://github.com/xarlord/btsec-testtool/commit/c533aa5145d3c59573a47b8b9f122d22fce57072))
* add local CI/CD scripts and fix Kotlin JVM target ([c383be4](https://github.com/xarlord/btsec-testtool/commit/c383be4a2f74e6cd584849b58857b139dcaf30ec))
* add Woodpecker CI pipeline and fix dashboard UI ([6fda07d](https://github.com/xarlord/btsec-testtool/commit/6fda07d1841cf2f9c3b363c1f38f76440b400e02))
* migrate from Woodpecker CI to Jenkins multi-agent pipeline ([01c624f](https://github.com/xarlord/btsec-testtool/commit/01c624fcf9c2c4d57321f377ea26e9dc0f079aa6))

## [1.1.4](https://github.com/xarlord/btsec-testtool/compare/v1.1.3...v1.1.4) (2026-02-07)


### Bug Fixes

* Update androidx.startup runtime version to valid release ([3730d44](https://github.com/xarlord/btsec-testtool/commit/3730d44dda922a9578138c3b497a71be2075650e))

## [1.1.3](https://github.com/xarlord/btsec-testtool/compare/v1.1.2...v1.1.3) (2026-02-07)


### Bug Fixes

* Update CI workflow to use correct test task names for product flavors ([65917ce](https://github.com/xarlord/btsec-testtool/commit/65917ce6d43a7eed11fc341b15496b3b0a749af0))

## [1.1.2](https://github.com/xarlord/btsec-testtool/compare/v1.1.1...v1.1.2) (2026-02-07)


### Bug Fixes

* Simplify dependency check configuration for compatibility ([a482410](https://github.com/xarlord/btsec-testtool/commit/a482410b65baf3177a83166e0655ba2a08a38f35))

## [1.1.1](https://github.com/xarlord/btsec-testtool/compare/v1.1.0...v1.1.1) (2026-02-07)


### Bug Fixes

* Correct dependency check configuration type mismatches ([10d9dda](https://github.com/xarlord/btsec-testtool/commit/10d9dda33f8d5cd52861b65d4e0948326279fbdb))

# [1.1.0](https://github.com/xarlord/btsec-testtool/compare/v1.0.1...v1.1.0) (2026-02-07)


### Features

* Add Jacoco and OWASP Dependency Check configuration ([0eed649](https://github.com/xarlord/btsec-testtool/commit/0eed649e303537ddb9f4546bb37f81a1351af846))

## [1.0.1](https://github.com/xarlord/btsec-testtool/compare/v1.0.0...v1.0.1) (2026-02-07)


### Bug Fixes

* Migrate all CI/CD jobs to macOS runners for AGP compatibility ([50a7c4d](https://github.com/xarlord/btsec-testtool/commit/50a7c4d0368d2c1b073786e2e5506f1a1c9d4a3c))

# 1.0.0 (2026-02-07)


### Features

* Initialize BTSec Test Tool - Bluetooth Vulnerability Testing Application ([00086ac](https://github.com/xarlord/btsec-testtool/commit/00086ac5f13cd2fada6fe2890bab3a4fe1029dae))
