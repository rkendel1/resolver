# Resolver on Fly.io

    fly apps create kendel-resolver
    fly volumes create resolver_data --region iad --size 1 -a kendel-resolver
    fly secrets set -a kendel-resolver RESOLVER_VAULT_KEY=<64 hex> RESOLVER_VERIFIER_KEY=<64 hex>
    fly deploy -a kendel-resolver
    fly ssh console -a kendel-resolver -C "resolver init --dir /data/.resolver --tenant kendel"   # prints the admin key once

Never change the vault or verifier key once set (everything stored depends on them); keep a copy.
One machine only: the volume belongs to one machine.
