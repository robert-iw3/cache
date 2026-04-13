# /etc/apparmor.d/bin.bash
#include <tunables/global>

profile bash /bin/bash {
  #include <abstractions/base>

  # Very restrictive - bash is often abused
  network inet,
  network inet6,

  /usr/lib/** r,
  /usr/share/** r,

  # Deny most external tools
  deny /usr/bin/curl x,
  deny /usr/bin/wget x,
  deny /usr/bin/nc x,
  deny /usr/bin/socat x,
  deny /usr/bin/python* x,

  owner @{HOME}/** rw,
  owner /tmp/** rw,

  audit deny /** w,
}