# /etc/apparmor.d/usr.bin.ruby
#include <tunables/global>

profile ruby /usr/bin/ruby* {
  #include <abstractions/base>

  network inet,
  network inet6,

  /usr/lib/** r,
  /usr/share/** r,

  deny /usr/bin/sh x,
  deny /usr/bin/bash x,
  deny /usr/bin/curl x,
  deny /usr/bin/wget x,

  owner @{HOME}/** rw,
  owner /tmp/** rw,

  audit deny /** w,
}