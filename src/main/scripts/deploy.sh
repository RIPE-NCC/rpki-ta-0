#!/bin/bash

###
# ========================LICENSE_START=================================
# RIPE NCC Trust Anchor
# -
# Copyright (C) 2017 RIPE NCC
# -
# Redistribution and use in source and binary forms, with or without modification,
# are permitted provided that the following conditions are met:
# 
# 1. Redistributions of source code must retain the above copyright notice, this
#    list of conditions and the following disclaimer.
# 
# 2. Redistributions in binary form must reproduce the above copyright notice,
#    this list of conditions and the following disclaimer in the documentation
#    and/or other materials provided with the distribution.
# 
# 3. Neither the name of the RIPE NCC nor the names of its contributors
#    may be used to endorse or promote products derived from this software without
#    specific prior written permission.
# 
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
# IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
# INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
# DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
# LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
# OF THE POSSIBILITY OF SUCH DAMAGE.
# =========================LICENSE_END==================================
###


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
