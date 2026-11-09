#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
#
# record-interop.sh OUTDIR — records real IEC 61850 traffic between the
# independent stacks of otfabric/iec61850-interop (pinned images, pulled
# beforehand) as pcap files: MMS and IEC 61850 client/server pairs on TCP
# 1102, GOOSE and Sampled Values publishers on the Docker bridge. tcpdump
# runs in a throwaway container that shares the server's (or publisher's)
# network namespace. Needs Docker and a checkout of iec61850-interop in
# $IEC61850_INTEROP (default ../iec61850-interop) for the GOOSE/SV fixtures.
set -euo pipefail

OUT="$(cd "${1:?usage: record-interop.sh OUTDIR}" && pwd)"
INTEROP="${IEC61850_INTEROP:-$(cd "$(dirname "$0")/../../iec61850-interop" && pwd)}"
REGISTRY=ghcr.io/otfabric
# The tcpdump helper: Alpine plus its tcpdump package.
ALPINE=docker.io/library/alpine:3.20
TCPDUMP=go-mms-trace-tcpdump:local

image_of() { docker images --format '{{.Repository}} {{.ID}}' | awk -v r="$REGISTRY/iec61850-interop-$1" '$1==r {print $2; exit}'; }
digest_of() { docker inspect "$1" --format '{{index .RepoDigests 0}}'; }

docker image inspect "$TCPDUMP" >/dev/null 2>&1 || printf 'FROM %s\nRUN apk add --no-cache tcpdump\n' "$ALPINE" | docker build -q -t "$TCPDUMP" - >/dev/null

MANIFEST="$OUT/recorded.jsonl"
[ -n "${ONLY:-}" ] || : > "$MANIFEST"
note() { # name kind server client
    printf '{"file":"%s.pcap","kind":"%s","server":"%s","client":"%s","serverImage":"%s","clientImage":"%s"}\n' \
        "$1" "$2" "$3" "$4" "$5" "$6" >> "$MANIFEST"
}

wait_ready() { # container
    local deadline=$((SECONDS + 30))
    while [ $SECONDS -lt $deadline ]; do
        docker logs "$1" 2>/dev/null | grep -q '"event":"ready"' && return 0
        sleep 0.2
    done
    echo "no ready event from $1" >&2; return 1
}

capture_start() { # container name filter
    docker run -d --name "cap-$2" --net "container:$1" --cap-add NET_RAW --cap-add NET_ADMIN \
        -v "$OUT:/out" "$TCPDUMP" tcpdump -i eth0 -U -s 0 -w "/out/$2.pcap" "$3" >/dev/null
    sleep 1
}
capture_stop() { docker stop -t 2 "cap-$1" >/dev/null; docker rm "cap-$1" >/dev/null; }

# pair_ NAME SERVER_ADAPTER SERVER_CMD CLIENT_ADAPTER CLIENT_CMD [CLIENT ARGS...]
pair_() {
    local name=$1 sa=$2 scmd=$3 ca=$4 ccmd=$5; shift 5
    local si ci net="mmstrace-$RANDOM" srv
    si=$(image_of "$sa"); ci=$(image_of "$ca")
    [ -n "$si" ] && [ -n "$ci" ] || { echo "skip $name: image missing" >&2; return; }
    srv="srv-$net"
    docker network create "$net" >/dev/null
    docker run -d --network "$net" --name "$srv" --entrypoint "$scmd" "$si" --port 1102 >/dev/null
    wait_ready "$srv"
    capture_start "$srv" "$name" "tcp port 1102"
    docker run --rm --network "$net" --entrypoint "$ccmd" "$ci" --host "$srv" --port 1102 "$@" > "$OUT/$name.client.jsonl" 2>/dev/null || true
    sleep 1
    capture_stop "$name"
    docker stop -t 2 "$srv" >/dev/null; docker rm "$srv" >/dev/null; docker network rm "$net" >/dev/null
    note "$name" mms "$scmd" "$ccmd" "$(digest_of "$si")" "$(digest_of "$ci")"
    echo "$name: $(grep -c '"ok":true' "$OUT/$name.client.jsonl" || true) ok, $(grep -c '"ok":false' "$OUT/$name.client.jsonl" || true) failed operations"
}

# publisher_ NAME ADAPTER goose|sv
publisher_() {
    local name=$1 a=$2 kind=$3 img fixture cb net="mmstrace-$RANDOM" pub field
    img=$(image_of "$a"); [ -n "$img" ] || { echo "skip $name" >&2; return; }
    fixture="$INTEROP/fixtures/$kind/$kind.json"
    local key=controlBlocks; [ "$kind" = sv ] && key=streams
    cb=$(python3 -c "import json;print(next(iter(json.load(open('$fixture'))['$key'])))")
    field() { python3 -c "import json,sys;v=json.load(open('$fixture'))['$key']['$cb'][sys.argv[1]];print(json.dumps(v) if isinstance(v,(list,dict)) else v)" "$1"; }
    pub="pub-$net"
    docker network create "$net" >/dev/null
    local args=(--iface eth0 --app-id "$(field appID)" --dst "$(field dst)")
    if [ "$kind" = goose ]; then
        args+=(--gocb-ref "$(field gocbRef)" --go-id "$(field goID)" --dataset "$(field datSet)" --values "$(field values)")
        local update; update=$(python3 -c "import json;print(json.dumps({'cmd':'set','values':json.load(open('$fixture'))['controlBlocks']['$cb']['update']}))")
        { sleep 3; echo "$update"; sleep 3; echo '{"cmd":"stop"}'; } | docker run -i --name "$pub" --network "$net" --cap-add NET_RAW \
            --entrypoint "$a-goose-publisher" "$img" "${args[@]}" > /dev/null 2>&1 &
        filter="ether proto 0x88b8"
    else
        args+=(--vlan-id "$(field vlanId)" --vlan-prio "$(field vlanPrio)" --sv-id "$(field svID)" --dataset "$(field datSet)"
            --conf-rev "$(field confRev)" --smp-rate "$(field smpRate)" --smp-mod "$(field smpMod)" --no-asdu "$(field noASDU)"
            --profile "$(field profile)" --values "$(field values)")
        { sleep 4; echo '{"cmd":"stop"}'; } | docker run -i --name "$pub" --network "$net" --cap-add NET_RAW \
            --entrypoint "$a-sv-publisher" "$img" "${args[@]}" > /dev/null 2>&1 &
        filter="ether proto 0x88ba"
    fi
    until docker inspect "$pub" >/dev/null 2>&1; do sleep 0.1; done
    capture_start "$pub" "$name" "$filter"
    wait || true
    capture_stop "$name"
    docker rm -f "$pub" >/dev/null 2>&1 || true; docker network rm "$net" >/dev/null
    note "$name" "$kind" "$a-$kind-publisher" "" "$(digest_of "$img")" ""
    echo "$name: recorded"
}

# ONLY: run just the named recordings (space-separated), for re-runs.
want() { [ -z "${ONLY:-}" ] || [[ " $ONLY " == *" $1 "* ]]; }
pair() { want "$1" && pair_ "$@" || true; }
publisher() { want "$1" && publisher_ "$@" || true; }

# MMS: the full service sequence of revision mms-v2.
pair libiec61850_mms-server_mms-client-iec61850-rust libiec61850 libiec61850-mms-server iec61850-rust iec61850-rust-mms-client
pair dscsystems_mms-server_mms-client-libiec61850 dscsystems dscsystems-mms-server libiec61850 libiec61850-mms-client
# IEC 61850 client/server, reports and controls across independent stacks.
pair libiec61850_ied-server_ied-client-iec61850bean libiec61850 libiec61850-ied-server iec61850bean iec61850bean-ied-client
pair iec61850bean_ied-server_ied-client-libiec61850 iec61850bean iec61850bean-ied-server libiec61850 libiec61850-ied-client
pair libiec61850_ied-server_ied-client-dscsystems libiec61850 libiec61850-ied-server dscsystems dscsystems-ied-client
pair libiec61850_ied-server_ied-client-cbsigma libiec61850 libiec61850-ied-server cbsigma cbsigma-ied-client
pair iec61850bean_ied-server_ied-reporter-libiec61850 iec61850bean iec61850bean-ied-server libiec61850 libiec61850-ied-reporter --trigger gi
pair libiec61850_ied-server_ied-reporter-iec61850-rust libiec61850 libiec61850-ied-server iec61850-rust iec61850-rust-ied-reporter --trigger gi
pair dscsystems_ied-server_ied-controller-libiec61850 dscsystems dscsystems-ied-server libiec61850 libiec61850-ied-controller --do SPCSO2 --ctlval true
# GOOSE and Sampled Values publishers.
publisher libiec61850_goose-publisher libiec61850 goose
publisher cbsigma_goose-publisher cbsigma goose
publisher libiec61850_sv-publisher libiec61850 sv
