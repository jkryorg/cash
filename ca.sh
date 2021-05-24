#!/bin/sh

set -e

MYCN=
MYALT=
MYSUBJECT=
CAOPTS=
COMMAND=
FORCE=false
OPENSSL_DIR="./pki"
OPTSTRING="a:c:d:s:fhn"
USAGE="usage: $(basename "$0") command [-${OPTSTRING}]"

die() {
    echo "$*" 1>&2
    exit 1
}

usage() {
    echo "$USAGE"
    exit 1
}

usage_full() {
    cat <<EOF
${USAGE}

commands:
    init            - initialize the CA configuration and keys
    sign            - sign certificate
    revoke          - revoke certificate
    clean           - revoke certificate and remove files
    gencrl          - update CRL file
    list            - list the CA inventory

options:
    -a altname      - add subjectAltName to certificate
    -d directory    - directory prefix (default: ${OPENSSL_DIR})
    -c cn           - common name of the certificate
    -s subject      - certificate subject (excluding common name)
    -f              - force re-signing if certificate exists
    -h              - show this help
    -n              - do not set password to CA private key
EOF
    exit 0
}

if [ $# -eq 0 ]; then
    usage
elif case "$1" in -*) false ;; esac; then
    COMMAND="$1"
    shift
fi

while getopts ":${OPTSTRING}" OPT; do
    case "$OPT" in
        a) MYALT="${MYALT:+"${MYALT},"}DNS:${OPTARG}" ;;
        c) MYCN="$OPTARG" ;;
        d) OPENSSL_DIR="$OPTARG" ;;
        f) FORCE=true ;;
        h) usage_full ;;
        n) CAOPTS="-nodes" ;;
        s) MYSUBJECT="$OPTARG" ;;
        *) die "Invalid option: -${OPTARG}" ;;
    esac
done

shift $((OPTIND - 1))

if [ -z "$COMMAND" ]; then
    if [ $# -eq 1 ]; then
        COMMAND="$1"
    else
        usage
    fi
elif [ $# -ne 0 ]; then
    die "Can't give command twice."
fi

OPENSSL_CONF="${OPENSSL_DIR}/CA/config"

if [ "$COMMAND" != "init" ]; then
    if [ ! -f "$OPENSSL_CONF" ]; then
        die "Missing ${OPENSSL_CONF}, run init first."
    fi
    if [ "$MYCN" = "ca" ]; then
        die "\"${MYCN}\" not allowed as common name."
    fi
fi

if [ -n "$MYCN" ]; then
    MYALT="DNS:${MYCN}${MYALT:+",${MYALT}"}"
    MYCRT="${OPENSSL_DIR}/certs/${MYCN}.crt"
    MYKEY="${OPENSSL_DIR}/private/${MYCN}.key"
    MYCSR="${OPENSSL_DIR}/requests/${MYCN}.csr"
fi

export OPENSSL_CONF OPENSSL_DIR

test_cn() {
    if [ -z "$MYCN" ] || [ -z "$MYCRT" ] || [ -z "$MYKEY" ] || [ -z "$MYCSR" ]; then
        die "Common name is required."
    fi
}

ca_init() {
    if [ -d "${OPENSSL_DIR}/CA" ]; then
        die "${OPENSSL_DIR}/CA already exists, aborting."
    fi

    mkdir -p "${OPENSSL_DIR}/CA/signed" "${OPENSSL_DIR}/certs" \
        "${OPENSSL_DIR}/private" "${OPENSSL_DIR}/requests"

    cat > "${OPENSSL_DIR}/CA/config" <<EOF
[ca]
default_ca = CA_default

[CA_default]
dir              = ${OPENSSL_DIR}
database         = \$dir/CA/index
serial           = \$dir/CA/serial
crlnumber        = \$dir/CA/crlnumber
new_certs_dir    = \$dir/CA/signed
private_key      = \$dir/CA/ca.key
certificate      = \$dir/certs/ca.crt
RANDFILE         = \$dir/private/.rand
default_days     = 1825
default_crl_days = 1825
default_md       = sha256
x509_extensions  = cert_ext
crl_extensions   = crl_ext
copy_extensions  = copy
policy           = default_policy
unique_subject   = no
name_opt         = ca_default
cert_opt         = ca_default
string_mask      = utf8only
utf8             = yes

[default_policy]
countryName            = optional
stateOrProvinceName    = optional
localityName           = optional
organizationName       = optional
organizationalUnitName = optional
commonName             = supplied
emailAddress           = optional

[req]
default_md             = sha256
x509_extensions        = ca_ext
distinguished_name     = req_distinguished_name

[req_distinguished_name]
countryName            = Country Name (2 letter code)
stateOrProvinceName    = State or Province Name
localityName           = Locality Name
organizationName       = Organization Name
organizationalUnitName = Organizational Unit Name
commonName             = Common Name
emailAddress           = Email Address

[ca_ext]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid
basicConstraints       = critical, CA:true
keyUsage               = critical, digitalSignature, cRLSign, keyCertSign

[cert_ext]
subjectKeyIdentifier   = hash
authorityKeyIdentifier = keyid
basicConstraints       = critical, CA:false
keyUsage               = critical, digitalSignature, keyEncipherment
extendedKeyUsage       = serverAuth, clientAuth

[crl_ext]
authorityKeyIdentifier = keyid
EOF

    touch "${OPENSSL_DIR}/CA/index"
    echo 01 > "${OPENSSL_DIR}/CA/serial"
    echo 01 > "${OPENSSL_DIR}/CA/crlnumber"

    openssl req $CAOPTS -x509 -new -days 3650 \
        -subj "${MYSUBJECT}/CN=${MYCN}" -newkey rsa:4096 \
        -keyout "${OPENSSL_DIR}/CA/ca.key" \
        -out "${OPENSSL_DIR}/certs/ca.crt"
    ca_gencrl
}

ca_gencrl() {
    openssl ca -gencrl -out "${OPENSSL_DIR}/certs/ca.crl"
}

ca_sign() {
    if [ ! -f "$MYKEY" ]; then
        openssl genrsa -out "$MYKEY" 4096
    fi

    if [ ! -f "$MYCSR" ]; then
        TEMPCONF="$(mktemp /tmp/req.XXXXXXXX)"
        # shellcheck disable=SC2064
        trap "rm -f ${TEMPCONF}" EXIT
        cat > "$TEMPCONF" <<EOF
[req]
default_md         = sha256
distinguished_name = req_distinguished_name
req_extensions     = req_ext
[req_distinguished_name]
[req_ext]
subjectAltName     = ${MYALT}
EOF
        openssl req -config "$TEMPCONF" -new \
            -subj "${MYSUBJECT}/CN=${MYCN}" \
            -key "$MYKEY" -out "$MYCSR"
    fi

    if [ -f "$MYCRT" ] && ! $FORCE; then
        die "${MYCRT} already exists, aborting."
    else
        openssl ca -batch -notext -in "$MYCSR" -out "$MYCRT"
    fi
}

ca_revoke() {
    if [ -f "$MYCRT" ]; then
        echo "Revoking ${MYCRT}"
        openssl ca -batch -revoke "$MYCRT"
        ca_gencrl
    else
        echo "No such file: ${MYCRT}"
    fi
}

ca_clean() {
    for _file in "$MYKEY" "$MYCSR" "$MYCRT"; do
        if [ -e "$_file" ]; then
            echo "Removing ${_file}"
            rm -f "$_file"
        fi
    done
}

case "$COMMAND" in
    init)
    test_cn
    ca_init
    ;;

    sign)
    test_cn
    ca_sign
    ;;

    revoke)
    test_cn
    ca_revoke
    ;;

    clean)
    test_cn
    ca_revoke || true
    ca_clean
    ;;

    gencrl)
    ca_gencrl
    ;;

    list)
    cat "${OPENSSL_DIR}/CA/index"
    ;;

    *)
    die "Invalid command: ${COMMAND}"
    ;;
esac
