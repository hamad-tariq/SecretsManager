# License and notices

Copyright 2026 Hammad Tariq.

Secrets Manager is licensed under the **[Apache License, Version 2.0](https://github.com/hamad-tariq/SecretsManager/blob/main/LICENSE)**, except `internal/crypto/shamir/shamir.go`, which is ported from [OpenBao](https://github.com/openbao/openbao) and remains under the **[Mozilla Public License 2.0](https://mozilla.org/MPL/2.0/)** (Copyright © HashiCorp, Inc.).

## What you may do

Use, modify and redistribute it for any purpose, commercial included, free of charge.

## What redistribution requires

If you redistribute it, modified or not, in source or binary form (Apache-2.0 §4), you must:

1. include a copy of the license;
2. mark files you changed;
3. keep the copyright, patent, trademark and attribution notices;
4. include the [`NOTICE`](https://github.com/hamad-tariq/SecretsManager/blob/main/NOTICE) file.

Also note the MPL-2.0 parts:

- changes to `shamir.go` must stay under MPL-2.0;
- the binaries include unmodified MPL-2.0 Go modules (such as `hashicorp/raft`), so tell recipients where their source is. [`THIRD_PARTY_NOTICES.md`](https://github.com/hamad-tariq/SecretsManager/blob/main/THIRD_PARTY_NOTICES.md) does that; ship it with your binaries.

## No warranty

The software is provided **"AS IS", WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND**, and the author and contributors are not liable for any damages arising from its use, including loss of data or secrets and security breaches (Apache-2.0 §§7–8).

## Trademarks and affiliation

No trademark rights are granted (Apache-2.0 §6). This is an independent project, not affiliated with or endorsed by Amazon Web Services, HashiCorp, the OpenBao project, Google, Microsoft or any other company. Product names are trademarks of their owners.

## Cryptography notice

This software includes cryptographic functionality. The country in which you reside may restrict the import, possession, use or re-export of encryption software. Check your country's laws before using or redistributing it.
