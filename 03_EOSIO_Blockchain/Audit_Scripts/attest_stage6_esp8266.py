import argparse
import hashlib
import json
import subprocess
import time
from pathlib import Path

SOURCE = Path.home() / (
    "IJAI_31343_Work/Revision_31343/"
    "Experimental_Results/Stage6/"
    "ESP8266_Agility/stage6_esp8266_run5_events.jsonl"
)

RUN_ID = 2026111505
EXPERIMENT = "Stage6_ESP8266_agility_run5"

CHAIN_ID = (
    "2e12b054397bacc59a55377af31766941"
    "c260b5c5731e1d2202e1bb821572755"
)

OUTPUT = Path("stage6_esp8266_eosio_results.jsonl")


def cleos(*args):
    command = [
        "sudo", "-n", "docker", "exec",
        "ijai-eosio-node",
        "cleos",
        "-u", "http://127.0.0.1:8888",
        *map(str, args)
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        timeout=40
    )

    if result.returncode != 0:
        raise RuntimeError(result.stderr or result.stdout)

    return result.stdout


def load_events():
    if not SOURCE.is_file():
        raise RuntimeError("Journal Stage 6 introuvable")

    events = []

    for line in SOURCE.read_text().splitlines():
        if not line.strip():
            continue

        event = json.loads(line)

        if (
            event.get("kind") == "epoch_activated"
            and event.get("experiment") == EXPERIMENT
        ):
            events.append(event)

    events.sort(key=lambda event: int(event["epoch"]))

    if len(events) != 18:
        raise RuntimeError(
            f"Attendu 18 epoques, trouve {len(events)}"
        )

    prepared = []

    for expected_epoch, event in enumerate(events, 1):
        epoch = int(event["epoch"])
        algorithm = int(event["algorithm"])

        expected_algorithm = 1 if epoch % 2 else 2

        if epoch != expected_epoch:
            raise RuntimeError("Sequence d'epoques incorrecte")

        if algorithm != expected_algorithm:
            raise RuntimeError("Alternance ECC incorrecte")

        if event.get("policy_mode") != "adaptive":
            raise RuntimeError("Politique inattendue")

        canonical = json.dumps(
            event,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True
        ).encode()

        digest = hashlib.sha256(canonical).hexdigest()

        prepared.append((epoch, algorithm, digest))

    return prepared


def get_rows():
    data = json.loads(
        cleos(
            "get", "table",
            "keyepoch", RUN_ID, "attests",
            "--limit", "1000"
        )
    )

    if data.get("more"):
        raise RuntimeError("Pagination inattendue")

    return data["rows"]


def find_row(rows, epoch):
    for row in rows:
        if (
            row["device"] == "testtag1"
            and int(row["epoch"]) == epoch
        ):
            return row

    return None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--commit",
        action="store_true",
        help="Soumettre les transactions EOSIO"
    )
    args = parser.parse_args()

    prepared = load_events()

    print("=== STAGE 6 : ATTESTATION MULTI-COURBES ===")
    print("Run ID :", RUN_ID)
    print("Nombre d'epoques :", len(prepared))

    for epoch, algorithm, digest in prepared:
        curve = "X25519" if algorithm == 1 else "P256"
        print(
            f"Epoch {epoch:02d} | "
            f"{curve:6s} | "
            f"SHA256 {digest[:16]}..."
        )

    if not args.commit:
        print("\nPREPARATION VALIDEE : AUCUNE TRANSACTION ENVOYEE")
        return

    info = json.loads(cleos("get", "info"))

    if info["chain_id"] != CHAIN_ID:
        raise RuntimeError("Identifiant blockchain incorrect")

    if "ijai *" not in cleos("wallet", "list"):
        raise RuntimeError("Portefeuille ijai verrouille")

    print("\nEOSIO : OK")

    last_block = 0

    for epoch, algorithm, digest in prepared:
        rows = get_rows()
        existing = find_row(rows, epoch)

        if existing:
            if existing["event_hash"].lower() != digest:
                raise RuntimeError(
                    f"Conflit d'empreinte a l'epoque {epoch}"
                )

            if (
                int(existing["algorithm"]) != algorithm
                or existing["policy"] != "adaptive"
                or existing["attester"] != "iotauth2"
            ):
                raise RuntimeError(
                    f"Conflit de metadonnees a l'epoque {epoch}"
                )

            print(f"EPOCH {epoch:02d} : DEJA PRESENTE")
            continue

        arguments = json.dumps([
            "iotauth2",
            "testtag1",
            RUN_ID,
            epoch,
            algorithm,
            "adaptive",
            digest
        ])

        start = time.perf_counter()

        response = json.loads(
            cleos(
                "push", "action",
                "keyepoch", "attest",
                arguments,
                "-p", "iotauth2@active",
                "-j")
        )

        latency = (
            time.perf_counter() - start
        ) * 1000

        processed = response.get("processed", {})
        receipt = processed.get("receipt") or {}

        if receipt.get("status") != "executed":
            raise RuntimeError(
                f"Transaction {epoch} non executee"
            )

        block = int(processed["block_num"])
        last_block = max(last_block, block)

        verified = find_row(get_rows(), epoch)

        if not verified:
            raise RuntimeError("Attestation absente")

        if (
            verified["event_hash"].lower() != digest
            or int(verified["algorithm"]) != algorithm
        ):
            raise RuntimeError(
                "Verification blockchain incorrecte"
            )

        record = {
            "run_id": RUN_ID,
            "epoch": epoch,
            "algorithm": algorithm,
            "event_hash": digest,
            "transaction_id": response.get("transaction_id"),
            "block_num": block,
            "submission_latency_ms": round(latency, 3)
        }

        with OUTPUT.open("a") as file:
            file.write(json.dumps(record) + "\n")

        print(
            f"EPOCH {epoch:02d} : EOSIO OK "
            f"| ALG={algorithm} "
            f"| LAT={latency:.2f} ms",
            flush=True
        )

    final_rows = get_rows()

    validated = 0

    for epoch, algorithm, digest in prepared:
        row = find_row(final_rows, epoch)

        if (
            row
            and row["event_hash"].lower() == digest
            and int(row["algorithm"]) == algorithm
            and row["policy"] == "adaptive"
            and row["attester"] == "iotauth2"
        ):
            validated += 1

    print("\nATTESTATIONS VERIFIEES :", validated, "/ 18")

    if validated != 18:
        raise RuntimeError("Verification finale incomplete")

    if last_block:
        irreversible = False

        for _ in range(40):
            info = json.loads(cleos("get", "info"))

            if (
                int(info["last_irreversible_block_num"])
                >= last_block
            ):
                irreversible = True
                break

            time.sleep(0.5)

        print(
            "DERNIER BLOC SOUMIS IRREVERSIBLE :",
            irreversible
        )

    print("STAGE 6 : AUDIT EOSIO TERMINE")


if __name__ == "__main__":
    main()
