# Hack4Gov Example Challenges

This directory is intended for locally supplied Hack4Gov/CTF challenge artifacts used to test the CTF Challenge Analysis Toolkit.

## Purpose

- Test automatic artifact triage
- Test recursive extraction and carving
- Test PCAP, image, archive, document, encoding, and binary analysis workflows
- Validate flag-detection logic against authorized CTF challenge files

## Usage

Place authorized challenge files and folders inside this directory, then upload them through the analyzer or use them as local test fixtures.

Example structure:

```text
examples/
└── hack4gov-challenges/
    ├── forensics/
    ├── network/
    ├── steganography/
    ├── crypto/
    ├── reverse-engineering/
    └── miscellaneous/
```

## Safety / Distribution

Only include challenge files that you are authorized to possess and redistribute. Avoid committing credentials, private competition infrastructure details, unreleased challenge material, or flags that should remain secret.
