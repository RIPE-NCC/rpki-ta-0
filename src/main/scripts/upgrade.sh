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

set -e

ARTIFACT=$1
APP_DIR=$2

WORK_DIR=./upgrading

mkdir -p ${WORK_DIR}
tar xzf ${ARTIFACT} -C ${WORK_DIR}

CURRENT_LINK_DIR=`readlink ${APP_DIR}/current`

NEW_ARTIFACT_DIR=`ls ${WORK_DIR}`

echo "NEW APP: ${NEW_ARTIFACT_DIR}"
echo "CURRENT APP: ${CURRENT_LINK_DIR}"

mv ${WORK_DIR}/${NEW_ARTIFACT_DIR} ${APP_DIR}
rm ${APP_DIR}/current
ln -sf ${NEW_ARTIFACT_DIR} ${APP_DIR}/current

rm -rf ${WORK_DIR}
rm -rf ${APP_DIR}/${CURRENT_LINK_DIR}

exit $?