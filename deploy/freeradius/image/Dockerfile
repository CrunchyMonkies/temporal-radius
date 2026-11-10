# FreeRADIUS 3.2 built with reverse CoA (CoA / Disconnect sent down RadSec connections that the
# NAS opened). Upstream compiles this out by default (src/include/features-h), and the official
# freeradius/freeradius-server images do not have it: they reject `type = auth+acct+coa`.
#
#   docker build -t <registry>/freeradius-radsec:<tag> deploy/freeradius/image
#
# FREERADIUS_REF is pinned to a v3.2.x commit because the reverse-CoA fixes listed for 3.2.11 are
# not in a tagged release yet. Switch it to release_3_2_11 once that tag exists.

ARG DEBIAN=debian:trixie-slim

FROM ${DEBIAN} AS build
ARG FREERADIUS_REF=9ec12490e6374b5201c55bd684bbbd1c1143c210
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl gcc make libc6-dev libssl-dev libtalloc-dev
WORKDIR /src
RUN curl -fsSL "https://github.com/FreeRADIUS/freeradius-server/archive/${FREERADIUS_REF}.tar.gz" \
    | tar -xz --strip-components=1
# Modules with missing optional libraries (LDAP, SQL drivers, ...) are skipped automatically;
# these sites only need the core server and rlm_always.
RUN CFLAGS="-O2 -DWITH_COA_TUNNEL" ./configure \
      --prefix=/usr --sysconfdir=/etc --localstatedir=/var \
      --disable-developer --without-rlm_perl --without-rlm_python3 \
 && make -j"$(nproc)" \
 && make install R=/out \
 && rm -rf /out/usr/include /out/usr/share/doc /out/usr/share/man /out/usr/lib/*.a /out/usr/lib/*.la

FROM ${DEBIAN}
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
 && apt-get install -y --no-install-recommends libssl3t64 libtalloc2 ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && groupadd -r -g 101 radius \
 && useradd -r -u 101 -g radius -M -d /etc/raddb -s /usr/sbin/nologin radius
COPY --from=build /out/ /
# Ship no sites or modules: the deployment mounts its own sites-enabled/ and mods-enabled/, and the
# stock ones (default, inner-tunnel, eap, ...) would open extra ports or fail without each other.
# clients.conf is emptied so the "localhost / testing123" example client does not exist.
RUN rm -f /etc/raddb/sites-enabled/* /etc/raddb/mods-enabled/* \
 && : > /etc/raddb/clients.conf \
 && mkdir -p /var/run/radiusd /var/log/radius \
 && chown -R root:radius /etc/raddb \
 && chown radius:radius /var/run/radiusd /var/log/radius \
 && radiusd -v | head -1
USER 101:101
EXPOSE 2083/tcp 3799/udp
ENTRYPOINT ["radiusd", "-f", "-l", "stdout"]
