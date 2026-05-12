"""
Copyright BOOSTRY Co., Ltd.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.

You may obtain a copy of the License at
http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.

See the License for the specific language governing permissions and
limitations under the License.

SPDX-License-Identifier: Apache-2.0
"""

import json
from pathlib import Path

MANIFEST_PATH = Path(".build/__local__.json")
OUTPUT_DIR = Path("output")
SKIP_SOURCE_PREFIXES = ("contracts/mock/", "contracts/.cache/")


def _is_output_target(contract_name: str, contract_type: dict) -> bool:
    source_id = contract_type.get("sourceId", "")
    if not source_id or source_id.startswith(SKIP_SOURCE_PREFIXES):
        return False

    return (
        source_id.startswith("contracts/token/")
        or source_id == "contracts/utils/Errors.sol"
    )


def _to_output_payload(contract_type: dict) -> dict:
    payload = {"abi": contract_type.get("abi", [])}

    bytecode = contract_type.get("deploymentBytecode", {}).get("bytecode", "0x")
    deployed_bytecode = contract_type.get("runtimeBytecode", {}).get("bytecode", "0x")
    if bytecode != "0x" or deployed_bytecode != "0x":
        payload["bytecode"] = bytecode
        payload["deployedBytecode"] = deployed_bytecode

    return payload


def main():
    OUTPUT_DIR.mkdir(exist_ok=True)

    with MANIFEST_PATH.open() as manifest_file:
        manifest = json.load(manifest_file)

    for contract_name, contract_type in manifest.get("contractTypes", {}).items():
        if not _is_output_target(contract_name, contract_type):
            continue

        output_path = OUTPUT_DIR / f"{contract_name}.json"
        with output_path.open("w") as output_file:
            json.dump(_to_output_payload(contract_type), output_file, indent=2)
            output_file.write("\n")


if __name__ == "__main__":
    main()
