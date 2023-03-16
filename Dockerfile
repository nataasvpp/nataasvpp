FROM debian:bullseye-slim as build
RUN apt-get -y update && apt-get -y install curl sudo clang make ninja-build cmake python3-ply python3-venv
RUN curl -s https://packagecloud.io/install/repositories/fdio/master/script.deb.sh | bash
RUN apt-get -y update && apt-get install -y libvppinfra libvppinfra-dev vpp-dev

# The VPP package modifies kernel parameters and starts daemon in post-install
#RUN apt-get download vpp
#RUN dpkg --unpack vpp*.deb
#RUN rm /var/lib/dpkg/info/vpp.postinst -f

COPY library.cmake /usr/lib/x86_64-linux-gnu/cmake/vpp/library.cmake
WORKDIR /build
COPY . .
RUN make pkg-deb-debug
RUN make pkg-deb

FROM scratch as artifact
COPY --from=build /build/_build/debug/NATaaSVPP-1.0.0-Linux.deb /nataasvpp-debug-1.0.0.deb
COPY --from=build /build/_build/release/NATaaSVPP-1.0.0-Linux.deb /nataasvpp-1.0.0.deb
