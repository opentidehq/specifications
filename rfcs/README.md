# RFCs

Request for Comments (RFCs) document significant specification changes before they land in `specs/`.

## Process

1. Open a GitHub [spec-change issue](../.github/ISSUE_TEMPLATE/spec-change.yml) (never Linear; opentide tracking is public GitHub only)
2. Draft an RFC from [0000-template.md](0000-template.md)
3. Maintainer review and acceptance
4. Update specs, fixtures, `SPECS.md`, and `CHANGELOG.md` in the same PR as the RFC, unless the request is for an RFC draft only
5. Implement opentide changes separately

## Index

| RFC | Title | Status |
|-----|-------|--------|
| [0001](0001-authority-model.md) | Authority model and change process | accepted |
| [0002](0002-vocabulary-versioning.md) | Vocabulary identifier versioning and schema pins | proposed |
| [0003](0003-per-key-vocabulary-versioning.md) | Per-key vocabulary versioning and schema pins | proposed |
| 0004 | Sysdig Falco deployer (reserved by issue #8; never landed, superseded by [0014](0014-sysdig-falco-platform.md)) | superseded |
| [0005](0005-scoped-signal-entities.md) | Stage-scoped `signal.entities`, and one prefixing rule for every staged vocabulary | accepted |
| [0005](0005-sharing-system.md) | Sharing system and MISP connector | accepted |
| [0006](0006-sharing-ci.md) | Sharing on the production merge | accepted |
| [0007](0007-elastic-security-platform.md) | Elastic Security detection platform | accepted |
| [0008](0008-rule-reviewed-date.md) | Optional review date on detection rules | draft |
| [0009](0009-machine-readable-vocabulary-contract.md) | A machine-readable vocabulary contract | draft |
| [0010](0010-deployment-external-ids.md) | Deployment external ids | accepted |
| [0011](0011-signal-reuse.md) | Signal reuse across detection objectives | draft |
| [0012](0012-rule-document-shape.md) | Rules should read like the other objects | draft |
| [0013](0013-visibility-logsource-is-a-dataset.md) | A log source is a dataset, with its columns | accepted |
| [0014](0014-sysdig-falco-platform.md) | Sysdig Secure and Falco detection platform | accepted |
| [0015](0015-yara-language.md) | One YARA language across detection platforms | accepted |
| [0016](0016-bitdefender-gravityzone-platform.md) | Bitdefender GravityZone detection platform | accepted |
| [0017](0017-graylog-platform.md) | Graylog detection platform (native event definitions) | accepted |
| [0018](0018-google-secops-yara-l.md) | Google Security Operations and the YARA-L language | accepted |

## Numbering

- Use four-digit zero-padded numbers: `0002`, `0003`, …
- Filename: `NNNN-short-kebab-title.md`
- `0000-template.md` is the template only — not a live proposal
