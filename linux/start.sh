#!/bin/bash
cd $(dirname $_)
chroot . /bin/appmapper.linux | /bin/tee appmapper.log
