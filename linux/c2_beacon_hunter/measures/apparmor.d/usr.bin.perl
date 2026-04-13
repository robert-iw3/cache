# /etc/apparmor.d/usr.bin.perl
#include <tunables/global>

profile perl /usr/bin/perl {
  #include <abstractions/base>

  network inet,
  network inet6,

  /usr/lib/** r,
  /usr/share/** r,

  deny /usr/bin/sh x,
  deny /usr/bin/bash x,
  deny /usr/bin/curl x,
  deny /usr/bin/wget x,
  deny /usr/bin/python* x,

  owner @{HOME}/** rw,
  owner /tmp/** rw,

  audit deny /** w,
}