#include <eosio/eosio.hpp>
#include <eosio/crypto.hpp>

using namespace eosio;

CONTRACT keyepoch : public contract {
public:
    using contract::contract;

    ACTION attest(
        name attester,
        name device,
        uint64_t run_id,
        uint64_t epoch,
        uint8_t algorithm,
        name policy,
        checksum256 event_hash
    ) {
        require_auth(attester);

        check(
            attester == "iotauth2"_n,
            "Unauthorized attestation account"
        );

        check(run_id > 0, "Invalid experiment ID");
        check(epoch > 0, "Invalid epoch");
        check(device.value != 0, "Invalid device");

        check(
            algorithm >= 1 && algorithm <= 3,
            "Unsupported ECC algorithm"
        );

        check(
            policy == "fixed"_n ||
            policy == "adaptive"_n,
            "Unsupported renewal policy"
        );

        attestations records(get_self(), run_id);

        auto index = records.get_index<"bydevepoch"_n>();

        uint128_t key =
            (static_cast<uint128_t>(device.value) << 64) |
            static_cast<uint128_t>(epoch);

        check(
            index.find(key) == index.end(),
            "Duplicate epoch attestation"
        );

        records.emplace(attester, [&](auto& row) {
            row.id = records.available_primary_key();
            row.attester = attester;
            row.device = device;
            row.epoch = epoch;
            row.algorithm = algorithm;
            row.policy = policy;
            row.event_hash = event_hash;
        });
    }

private:
    TABLE epoch_record {
        uint64_t id;
        name attester;
        name device;
        uint64_t epoch;
        uint8_t algorithm;
        name policy;
        checksum256 event_hash;

        uint64_t primary_key() const {
            return id;
        }

        uint128_t by_device_epoch() const {
            return
                (static_cast<uint128_t>(device.value) << 64) |
                static_cast<uint128_t>(epoch);
        }
    };

    typedef multi_index<
        "attests"_n,
        epoch_record,
        indexed_by<
            "bydevepoch"_n,
            const_mem_fun<
                epoch_record,
                uint128_t,
                &epoch_record::by_device_epoch
            >
        >
    > attestations;
};
