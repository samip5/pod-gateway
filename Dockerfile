FROM alpine:3.20.3@sha256:1e42bbe2508154c9126d48c2b8a75420c3544343bf86fd041fb7527e017a4b4a
WORKDIR /

# iproute2 -> bridge
# bind-tools -> dig, bind
# dhclient -> get dynamic IP
# dnsmasq-dnssec -> DNS & DHCP server with DNSSEC support
# coreutils -> need REAL chown and chmod for dhclient (it uses reference option not supported in busybox)
# bash -> for scripting logic
# inotify-tools -> inotifyd for dnsmask resolv.conf reload circumvention
RUN apk add --no-cache coreutils dnsmasq-dnssec iproute2 bind-tools dhclient bash inotify-tools ip6tables

COPY config /default_config
COPY config /config
COPY bin /bin
CMD [ "/bin/entry.sh" ]

ARG IMAGE_SOURCE
#https://github.com/k8s-at-home/template-container-image
LABEL org.opencontainers.image.source $IMAGE_SOURCE
