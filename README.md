# ca.sh - private CA helper script

ca.sh aims to make managing your private CA slightly less painful than
stabbing yourself in the eye.

## Getting started

Initialize the CA configuration and certificates:

    ca.sh -c "My CA" init

Sign a certificate with alternative names:

    ca.sh -c localhost.localdomain -a alt1.localdomain -a alt2.localdomain sign

Revoke and remove certificate:

    ca.sh -c localhost.localdomain clean

See `ca.sh -h` for all available options and commands.
