#!/bin/bash

# shellcheck disable=SC2006
# shellcheck disable=SC2086

set -e

BOLD_FONT="\e[1m"
GREEN_FONT="\e[92m"
RED_FONT="\e[31m"
PURPLE_FONT="\e[95m"
YELLOW_FONT="\e[93m"
RESET_FONT="\e[0m"

echo -e "$BOLD_FONT"

SSH_KEY=${1}
ARTIFACT=${2}
NODES=${3}

SSH_FLAGS="-4 -oStrictHostKeyChecking=no"

echo -e "$YELLOW_FONT"

echo "##################################################################"
echo "##################################################################"
echo "Start work on:"
echo "    Node -> ${NODES} "
echo "    Artifacts -> ${ARTIFACT} "
echo "##################################################################"
echo "##################################################################"


for node in ${NODES}
do
    echo ""
    echo ""
    echo "Start deployment on ${node}."

    echo -e "$PURPLE_FONT"
    ssh ${SSH_FLAGS} -i ${SSH_KEY} rpkideploy@${node} -C "rm -rf deploy_work_dir && mkdir deploy_work_dir"
    scp ${SSH_FLAGS} -i ${SSH_KEY} src/main/scripts/upgrade.sh ${ARTIFACT} rpkideploy@${node}:./deploy_work_dir
    ssh ${SSH_FLAGS} -i ${SSH_KEY} rpkideploy@${node} -C "cd ./deploy_work_dir && ./upgrade.sh ${ARTIFACT} /export/bad/apps/rpki-ta-0"
    echo -e "$YELLOW_FONT"

    echo "Deployment done on ${node}."
    echo "------------------------------------------------"
    echo "------------------------------------------------"
    echo ""
    echo ""
done

echo -e "$RESET_FONT"
exit 0
