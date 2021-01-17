TODO(keefertaylor): remove this before open sourcing.

msig: KT1AwQcZCN9ehBG82k1VGqrfHvJ17ZCoUW59
store: KT1BC1RDjV6oc4JxPgUfwk65DN2j4xupZtEa

address: tz1YfB2H1NoZVUq4heHqrVX4oVp99yz8gwNq
sig: sig: edsigtq5EbVX4VYBMPmJ6X9wJvFDv4Qkrh18Ni9qTt3FypKEmdig2PXyYAjXyFqh19Smem8n8KgNkH52CCAAhHVHmWepr6q3Mwq

ts-node src/index.ts bytes --target-contract KT1BC1RDjV6oc4JxPgUfwk65DN2j4xupZtEa --target-entrypoint replace --target-arg "sp.nat(2)" --node-url https://rpctest.tzbeta.net --multisig-address KT1AwQcZCN9ehBG82k1VGqrfHvJ17ZCoUW59

0x0507070a00000004a836502107070001020000004e0320053d036d0743036e0a00000016011c9a5fb5260be9366a1b2445d5d43c1f5ad1489a00055503620200000010072f0200000004034f032702000000000743036a0000074303620002034d031b

tezos-client -P 443 -S -A rpctest.tzbeta.net sign bytes  050707010000000f4e6574586d387459716e4d576b793109070000005e00010320053d036d0743036e01000000244b543142433152446a56366f63344a7850675566776b3635444e326a347875705a744561055503620200000010072f0200000004034f032702000000000743036a0000074303620002034d031b00000000 for harbinger-carthagenet

tezos-client -P 443 -S -A rpctest.tzbeta.net transfer 0 from harbinger-carthagenet to KT1AwQcZCN9ehBG82k1VGqrfHvJ17ZCoUW59 
--arg  'Pair {Elt "tz1YfB2H1NoZVUq4heHqrVX4oVp99yz8gwNq" "edsigtq5EbVX4VYBMPmJ6X9wJvFDv4Qkrh18Ni9qTt3FypKEmdig2PXyYAjXyFqh19Smem8n8KgNkH52CCAAhHVHmWepr6q3Mwq"; } (Pair "NetXm8tYqnMWky1"        (Pair 1 { DROP; NIL operation; PUSH address "KT1BC1RDjV6oc4JxPgUfwk65DN2j4xupZtEa"; CONTRACT %replace nat;                 IF_SOME {} { UNIT; FAILWITH }; PUSH mutez 0; PUSH nat 1; TRANSFER_TOKENS; CONS }))' --entrypoint 'addExecutionRequest'