#!/usr/bin/env python3
"""Vendor Payment Cryptography data plane request constraints from botocore's Apache-2.0 service model.

`PaymentCryptographyDataRequestShapes` checks the data plane's actions against the vendored file
through the shared `RequestConstraintCheck`: member types, required members, lengths and counts,
patterns and enum values, as the model states them. The patterns are what settle which key a
request may name: `KeyIdentifier` takes the ARN of a key, the ARN of an alias or the name of an
alias, and the identifier of a key on its own names none of them.

The data plane is a service of its own, so its constraints are vendored in a file of their own,
as the control plane's are.

Run from anywhere in the repo:
    python3 tools/aws/regen_payment_cryptography_data_shapes.py            # rewrite the vendored file in place
    python3 tools/aws/regen_payment_cryptography_data_shapes.py --check    # exit 1 when the vendored file is stale
"""
from __future__ import annotations

import sys
from pathlib import Path

import request_shapes

OUTPUT = request_shapes.REPO_ROOT / "src/main/resources/aws/payment-cryptography-data-request-shapes.json"
MODEL = Path("payment-cryptography-data/2022-02-03")
OPERATIONS = (
    "EncryptData", "DecryptData", "ReEncryptData",
    "GenerateMac", "VerifyMac",
    "GeneratePinData", "VerifyPinData", "TranslatePinData", "GenerateMacEmvPinChange",
    "GenerateCardValidationData", "VerifyCardValidationData",
    "GenerateAuthRequestCryptogram", "VerifyAuthRequestCryptogram",
    "GenerateAs2805KekValidation",
    "TranslateKeyMaterial",
)

# The partition the model writes in its ARN patterns, and the one the service writes in
# every partition it serves.
COMMERCIAL = "arn:aws:"
EVERY_PARTITION = "arn:aws[a-z0-9-]*:"

# The region the model writes in its ARN patterns and on `Region`, which fits the commercial
# partition's two-part prefix alone, and the one that fits every published region: `us-gov-west-1`
# has a further part and `eusc-de-east-1` a longer prefix.
COMMERCIAL_REGION = "[a-z]{2}-[a-z]{1,16}-[0-9]+"
EVERY_REGION = "[a-z]{2,4}(-[a-z]{1,16})+-[0-9]+"


def widen_partition_and_region(model: dict) -> dict:
    """The model's patterns, with the partition and the region they name widened to every partition's.

    The model writes the commercial partition and regions of its shape, as the service's own model
    need not name the others, but the service mints and takes the ARN of the partition and the
    region a key is in, so the check must not refuse the ARN of a key outside the commercial one.
    """
    for shape in model["shapes"].values():
        pattern = shape.get("pattern")
        if pattern:
            shape["pattern"] = pattern.replace(COMMERCIAL, EVERY_PARTITION).replace(COMMERCIAL_REGION, EVERY_REGION)
    return model


def main(argv: list[str] | None = None) -> int:
    return request_shapes.main(argv, script=__file__, model=MODEL, output=OUTPUT,
                               description=__doc__, operations=OPERATIONS,
                               prepare=widen_partition_and_region)


if __name__ == "__main__":
    sys.exit(main())
