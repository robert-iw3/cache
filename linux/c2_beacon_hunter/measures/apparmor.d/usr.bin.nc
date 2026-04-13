# /etc/apparmor.d/usr.bin.nc
#include <tunables/global>

profile nc /usr/bin/nc /usr/bin/netcat {
  #include <abstractions/base>

  network inet,
  network inet6,

  # Netcat is a classic C2 tool
  deny /usr/bin/sh x,
  deny /usr/bin/bash x,
  deny /usr/bin/python* x,
  deny /usr/bin/curl x,
  deny /usr/bin/wget x,
  deny /usr/bin/socat x,
  deny /usr/bin/openssl x,

  owner @{HOME}/** rw,
  owner /tmp/** rw,

  audit deny /** w,
}