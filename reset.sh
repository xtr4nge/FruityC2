#!/bin/bash

echo "--------------------------------"
echo "BACKUP DATA, CONFIGS AND LOGS  "
echo "--------------------------------"
DIR="_BACKUP_"
if [ ! -d "$DIR" ]; then
	#cmd=`date +"%Y-%m-%d-%H-%M-%S"`
	mkdir $DIR
	#echo
fi

if [ -d "$DIR" ]; then
	DATE=`date +"%Y-%m-%d-%H-%M-%S"`
	CDIR=$DIR/$DATE
    echo $CDIR
    
    DATA="data"
    CONFIG="config"
    LOGS="logs"
    
    mkdir $CDIR
    
    # BACKUP DATA
    echo " > $DATA"
    mv $DATA $CDIR
    
    # BACKUP CONFIG
    echo " > $CONFIG"
    cp -a config $CDIR
    
    # BACKUP LOGS
    echo " > $LOGS"
    mv logs $CDIR
    
	echo
    
    echo "--------------------------------"
    echo "RESET                           "
    echo "--------------------------------"
    
    # RESET DATA
    echo " > $DATA"
    mkdir $DATA
    touch $DATA/credentials.json
    touch $DATA/credentials_spn.json
    touch $DATA/credentials_ticket.json
    mkdir $DATA/downloads
    mkdir $DATA/screenshots
    
    # RESET CONFIG
    echo " > $CONFIG"
    echo "{}" > $CONFIG/listener.json
    echo "{}" > $CONFIG/payload.json
    echo "{}" > $CONFIG/target.json
    echo "{}" > $CONFIG/web_delivery.json
    
    # RESET LOGS
    echo " > $LOGS"
    mkdir $LOGS
    mkdir $LOGS/target
    touch $LOGS/alert.json
    touch $LOGS/chat.json
    touch $LOGS/data.json
    touch $LOGS/target.json
    
    echo
fi