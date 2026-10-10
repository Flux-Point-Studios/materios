# Seat-key probe

Lists the session keys a running Materios validator's keystore holds, without
an RPC call. Ceremonies use it to map each FPS host to its committee seat and to
refuse a seat held on two hosts.

## Why not `author_hasKey`

`author_hasKey` is an unsafe RPC method. A validator on `--rpc-methods safe`
refuses it with `-32601 "RPC call is unsafe to be called externally"`, so a
ceremony that asks it fails closed once the fleet's RPC is locked down.

At polkadot-stable2409-4 (`c455194`), `author_hasKey` answers from the key file
alone. `LocalKeystore::has_keys` opens `<keystore>/<hex key type><hex public>`
and parses it as a JSON string (`substrate/client/keystore/src/local.rs:166`,
`:512`, `:556`). It does not check that the secret derives the public key.

This probe reads the same file names in the same directory:

| Step | How the probe does it |
|---|---|
| Find the node | The one `materios-node*` process with `--validator` whose `--chain` ends in `--chain-suffix`; zero or several refuse. |
| Find its keystore | `--keystore-path`, else `<--base-path>/chains/<chain spec id>/keystore`, the way sc-cli resolves it (`keystore_params.rs:78-81`, `run_cmd.rs:584-595`). The spec id comes from the file the node's `--chain` names. Paths resolve inside the node's root and working directory, so a containerised node works. |
| Check each key | A file named `<hex key type><lowercase hex public>` that is a regular file the node's user can read. |

The one thing `author_hasKey` checked that this probe does not is that the file
parses as JSON. The probe never opens a key file, because the file holds the
secret. To prove a seat's keys actually sign, use the chain: blocks authored in
that seat's Aura slots, and its GRANDPA precommits in justifications.

## Run

On the validator host, as the node's user, with the standard library only:

```
ssh HOST python3 - --chain-suffix chain-spec-v6-raw.json aura gran < seat_keys.py
```

It prints one JSON object and exits 0:

```json
{"pid": 6161,
 "keystore": "/srv/materios/data/chains/materios_preprod_v6/keystore",
 "held": {"aura": ["0x1a2b…"], "gran": ["0x3c4d…"]},
 "unreadable": {"aura": [], "gran": []}}
```

`held` lists every key of that type in the keystore. Intersect it with the
committee yourself. `unreadable` lists key files the node cannot open: a
dangling link, a directory, or a file its user lacks read access to.

## Refusals

It exits 2 with the reason on stderr, and prints nothing on stdout, when:

- not exactly one validator process runs a matching chain spec;
- the node runs as another user, since file access is judged as the node judges it;
- the keystore is temporary (`--tmp`, or `--dev` with no base path);
- the node has no `--base-path` and no `--keystore-path`;
- an option is given twice, or has no value;
- `--chain` is not a readable chain spec file, or the spec has no `id`;
- the keystore directory does not exist;
- a key type is not 4 ASCII bytes.

## Test

```
python3 -m pytest -q -p no:cacheprovider test_seat_keys.py
```
