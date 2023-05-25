# SSH-Harvester

Harvest passwords automatically from OpenSSH server

Tested on OpenSSH portable 8.2p1 and 9.3p1.

For testing purposes, download a OpenSSH stable release from [mirrors](https://www.openssh.com/portable.html#downloads)

## How to use

Just use [emp3r0r](https://github.com/jm33-m0/emp3r0r) when possible. However, if you find bugs of this C version, please send a fix

```
sudo ./start_sshd.sh

# in another terminal
./inject.sh

# then
ssh -p2222 user@localhost

# check what happens
```

## How does it work

https://github.com/jm33-m0/SSH-Harvester/assets/10167884/f22835f3-7281-4c31-829f-a2aee40f1cf9

See my [blog post](https://jm33.me/sshd-injection-and-password-harvesting.html)
