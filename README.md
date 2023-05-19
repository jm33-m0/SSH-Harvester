# SSH-Harvester

Harvest passwords automatically from OpenSSH server

Tested on OpenSSH portable 8.2p1 and 9.3p1.

For testing purposes, download a OpenSSH stable release from [mirrors](https://www.openssh.com/portable.html#downloads)

## How to use

```
sudo ./start_sshd.sh

# in another terminal
./inject.sh

# then
ssh -p2222 user@localhost

# check what happens
```

## How does it work

I will write a blog soon, see [jm33.me](https://jm33.me)
