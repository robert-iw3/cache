#!/bin/bash
# generate_apparmor_profiles.sh
# Dynamically generates basic restrictive AppArmor profiles for binaries in /usr/bin

OUTPUT_DIR="/etc/apparmor.d"
mkdir -p "$OUTPUT_DIR"

echo "Generating AppArmor profiles for /usr/bin ..."

for bin in /usr/bin/*; do
    if [ -x "$bin" ] && [ ! -d "$bin" ]; then
        name=$(basename "$bin")
        profile_file="$OUTPUT_DIR/usr.bin.$name"

        cat > "$profile_file" << EOF
# /etc/apparmor.d/usr.bin.$name
#include <tunables/global>

profile $name $bin {
  #include <abstractions/base>

  # Network access (common for many tools)
  network inet,
  network inet6,

  # Read system libraries
  /usr/lib/** r,
  /usr/share/** r,
  /etc/** r,

  # Deny execution of shells and dangerous tools
  deny /usr/bin/sh x,
  deny /usr/bin/bash x,
  deny /usr/bin/python* x,
  deny /usr/bin/perl x,
  deny /usr/bin/ruby x,
  deny /usr/bin/curl x,
  deny /usr/bin/wget x,
  deny /usr/bin/nc x,
  deny /usr/bin/socat x,

  # Allow writing only to user home and /tmp
  owner @{HOME}/** rw,
  owner /tmp/** rw,

  audit deny /** w,
}
EOF
        echo "Generated: $profile_file"
    fi
done

echo "All profiles generated. Now load them with:"
echo "sudo apparmor_parser -r $OUTPUT_DIR/usr.bin.*"
echo "sudo aa-enforce $OUTPUT_DIR/usr.bin.*"