#include <eosio/eosio.hpp>

using namespace eosio;

class [[eosio::contract]] iotauth2 : public contract {
public:
    using contract::contract;

    // Enregistrement d'un equipement
    [[eosio::action]]
    void enroll(name rfid_tag, name authorized_account) {

        require_auth(get_self());

        check(is_account(authorized_account),
              "Authorized account does not exist");

        auth_table devices(get_self(), get_self().value);

        auto existing = devices.find(rfid_tag.value);

        check(existing == devices.end(),
              "RFID tag already registered");

        devices.emplace(get_self(), [&](auto& row) {
            row.rfid_tag = rfid_tag;
            row.authorized_account = authorized_account;
            row.last_nonce = 0;
        });
    }

    // Verification de l'autorisation du compte EOSIO
    [[eosio::action]]
    void authenticate(name authorizing_account,
                      name rfid_tag,
                      uint64_t nonce) {

        require_auth(authorizing_account);

        auth_table devices(get_self(), get_self().value);

        auto existing = devices.find(rfid_tag.value);

        check(existing != devices.end(),
              "RFID tag not found");

        check(existing->authorized_account ==
              authorizing_account,
              "Unauthorized account");

        check(nonce > existing->last_nonce,
              "Nonce already used");

        devices.modify(existing, get_self(), [&](auto& row) {
            row.last_nonce = nonce;
        });
    }

private:

    struct [[eosio::table]] auth_data {
        name rfid_tag;
        name authorized_account;
        uint64_t last_nonce;

        uint64_t primary_key() const {
            return rfid_tag.value;
        }
    };

    typedef multi_index<"authdata"_n, auth_data> auth_table;
};

EOSIO_DISPATCH(iotauth2, (enroll)(authenticate))
