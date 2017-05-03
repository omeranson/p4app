type the following commands in the mininet cli:
h2 python receive.py h2-eth0 > h2.log &
h1 python send.py h2 h1-eth0

You can see the output by looking at the h2.log in the container
