### Added Features

- add support for Gemfile.next.lock [[#4457](https://github.com/anchore/syft/pull/4457) @HatiCode]
- Command output to give more information on what catalogers look for and what they can find [[#4155](https://github.com/anchore/syft/issues/4155) [#4317](https://github.com/anchore/syft/pull/4317) @wagoodman]
- Support reading lzma compressed `.go.buildinfo` sections with upx [[#4411](https://github.com/anchore/syft/issues/4411) [#4480](https://github.com/anchore/syft/pull/4480) @wagoodman]
- Specify specific snap revision to pull [[#4389](https://github.com/anchore/syft/issues/4389) [#4439](https://github.com/anchore/syft/pull/4439) @VictorHuu]
- Cannot detect embedded deps.json metadata in single-file .NET binaries [[#4344](https://github.com/anchore/syft/issues/4344) [#4375](https://github.com/anchore/syft/pull/4375) @rezmoss]
- ELF note cataloger does not pick up OS field, but should [[#4384](https://github.com/anchore/syft/issues/4384) [#4438](https://github.com/anchore/syft/pull/4438) @VictorHuu]

### Bug Fixes

- remove debug print statement in dependency parser [[#4412](https://github.com/anchore/syft/pull/4412) @cgreeno]
- dotnet-deps cataloger should skip project references with type "project" when building the sbom [[#4423](https://github.com/anchore/syft/issues/4423) [#4436](https://github.com/anchore/syft/pull/4436) @rezmoss]
- File digests not computed when using `--base-path` [[#4410](https://github.com/anchore/syft/issues/4410) [#4478](https://github.com/anchore/syft/pull/4478) @wagoodman]
- Syft should not define subpaths by default in PURLs [[#4394](https://github.com/anchore/syft/issues/4394) [#4395](https://github.com/anchore/syft/pull/4395) @rezmoss]
- go: valid purl but incorrect name [[#1737](https://github.com/anchore/syft/issues/1737) [#4395](https://github.com/anchore/syft/pull/4395) @rezmoss]
- Incorrect Go module PURL generation when module path contains /vN (e.g. /v5) [[#4316](https://github.com/anchore/syft/issues/4316) [#4395](https://github.com/anchore/syft/pull/4395) @rezmoss]
- Failing to convert npm repository information correctly to SPDX [[#4362](https://github.com/anchore/syft/issues/4362) [#4390](https://github.com/anchore/syft/pull/4390) @kendrickm]

**[(Full Changelog)](https://github.com/anchore/syft/compare/v1.38.2...v1.39.0)**
