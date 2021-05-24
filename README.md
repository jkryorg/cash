# ca.sh - private CA helper script

ca.sh aims to make managing your private CA slightly less painful than
stabbing yourself in the eye.

## Getting started

Initialize the CA configuration and certificates:

    ca.sh init -c "My CA"

Sign a certificate with alternative names:

    ca.sh sign -c localhost.localdomain -a alt1.localdomain -a alt2.localdomain

Revoke and remove certificate:

    ca.sh clean -c localhost.localdomain

See `ca.sh -h` for all available commands and options.
