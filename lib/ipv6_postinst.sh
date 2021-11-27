cat >/target/etc/network/interfaces.d/ens192_ipv6.conf <<EOF 
iface end192 inet6 static
    address {}
    netmask 64
    gateway fe80::1
    privext 0
    accept_ra 0
    dad-attempts 0
EOF
echo nameserver 2001:7c0:2053:: >> /target/etc/resolv.conf

