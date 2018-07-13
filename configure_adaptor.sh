#!/bin/bash

readonly ADAPTOR=$1

if [[ -z $ADAPTOR ]]; then
	printf "Argument required: adaptor\n\n"
	exit 1
fi

sudo ifconfig $ADAPTOR down
sudo iwconfig $ADAPTOR mode monitor
sudo ifconfig $ADAPTOR up
