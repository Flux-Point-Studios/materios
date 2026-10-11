# Seat-key probe

Lists the session keys a running Materios validator's keystore names, without
an RPC call. Ceremonies use it to refuse a seat held on two hosts, so it fails
closed: when it answers, `named` leaves out no key the node can sign with.

`named` is an upper bound on what the node holds, never evidence that it holds
a key. A key named on exactly one probed host Y proves that no other probed host
signs with it, never that Y does. A positive claim that a host serves a seat
comes from the chain alone: blocks authored in that seat's Aura slots, and its
GRANDPA precommits in justifications.

## Why not `author_hasKey`

`author_hasKey` is an unsafe RPC method. A validator on `--rpc-methods safe`
refuses it with `-32601 "RPC call is unsafe to be called externally"`, so a
ceremony that asks it fails closed once the fleet's RPC is locked down.

At polkadot-stable2409-4 (`c455194`), `LocalKeystore::has_keys` answers from
two places (`substrate/client/keystore/src/local.rs:166`, `:512-526`, `:556`):

1. an in-memory map, which holds the dev seed's keys of a node started with a
   keyring flag (`--alice` … `--two`, or `--dev`), and nothing otherwise;
2. the file `<keystore>/<hex key type><hex public>`, parsed as a JSON string.

It does not check that the secret derives the public key.

## How the probe answers

| Step | How the probe does it |
|---|---|
| Find the node | Every process with an authority flag of its own: `--validator`, a keyring flag or `--dev` (sc-cli `run_cmd.rs:413-416`), whatever its binary is called. |
| Tell its chain | The chain spec id whose database the process holds open at `<--base-path>/chains/<id>/db` or `paritydb`, read from `/proc/<pid>/fd`. The node read its spec once, at its start: the file its `--chain` names may hold another spec by now, and a spec built into the node (`--chain preprod`) has no file. The kernel names an open file by its resolved path, so the base path must be absolute without `..`, and a database open anywhere else (a link into another chain's tree, a base path that is itself a link) refuses. |
| Pick one | Exactly one authority process must run the asked chain. Any authority process whose chain cannot be told refuses the probe too, since it may be that one. |
| Refuse dev keys | A node with a keyring flag or `--dev` holds keys no file shows. |
| Find its keystore | `--keystore-path`, else `<--base-path>/chains/<id>/keystore`, the way sc-cli resolves it (`keystore_params.rs:78-81`, `run_cmd.rs:584-595`). |
| Walk to it | From the node's root (`/proc/<pid>/root`) for an absolute path, its working directory (`/proc/<pid>/cwd`) for a relative one, one directory at a time. A containerised node's paths resolve in its own filesystem. A symbolic link or `..` on the path refuses: the node follows a link from its own root, and the kernel would follow it from the probe's. |
| List the keys | Every entry named `<hex key type><lowercase hex public>`. |

`named` lists every key entry, whatever it is. The probe cannot judge what the
node can open: that turns on the node's fsuid, groups, capabilities, ACLs and
security modules. So `named` may include a key the node cannot read, but never
leaves out one it can.

The probe never opens a key file, because the file holds the secret. So it
cannot check that a file parses as JSON, as `author_hasKey` does.

## Run

On the validator host, as the node's user or root, with Python 3.10 or newer
and the standard library only:

```
ssh HOST python3 - --chain-id materios_preprod_v6 aura gran < seat_keys.py
```

It prints one JSON object and exits 0:

```json
{"pid": 6161,
 "chain_id": "materios_preprod_v6",
 "keystore": "/srv/materios/data/chains/materios_preprod_v6/keystore",
 "named": {"aura": ["0x1a2b…"], "gran": ["0x3c4d…"]}}
```

Intersect `named` with the committee yourself. On a host whose `/proc` is
mounted with `hidepid`, run it as root, or another user's validator is
invisible to it.

## Refusals

It exits 2 with the reason on stderr, and prints nothing on stdout, when:

- `/proc` cannot be listed, or an authority process's argv, open files or root
  cannot be read;
- not exactly one authority process runs the asked chain;
- an authority process has no `--base-path`, a relative one or one with `..`,
  holds no chain database open, holds two chains' databases, or holds one
  anywhere but `<--base-path>/chains/<id>/db` or `paritydb`;
- the node runs with a keyring flag or `--dev`;
- the keystore is temporary (`--tmp`);
- an option is given twice, or has no value;
- the keystore path holds a symbolic link or `..`, or a step on it is missing
  or not a directory;
- a key type is not 4 ASCII bytes;
- Python is older than 3.10.

## Test

```
python3 -m pytest -q -p no:cacheprovider test_seat_keys.py
```
