## Running of Wireshark GUI through XServer from docker container under macOS

1. Install XQuartz: https://www.xquartz.org/
2. Enable network connections in `XQuartz`: `Preferencec/Security/Allow connections from network clients`
3. Determine ip address of your network card, `ifconfig` is your friend, `localhost` will not work.
4. Run:
    `xhost + 192.168.0.1`
   where `192.168.0.1` is replaced with your real ip address.
5. Run docker with GUI app and host network mode:
    `docker run --net=host -e "DISPLAY=192.168.0.1:0" --volume="$HOME/.Xauthority:/root/.Xauthority:rw" -u appuser -it 357b7aec567d /opt/wireshark/build/run/wireshark`.
   Again, use your real ip address instead of `192.168.0.1`.