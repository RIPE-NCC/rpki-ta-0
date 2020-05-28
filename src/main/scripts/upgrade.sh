#!/bin/bash
#
# Copyright © 2017, RIPE NCC
# All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the <organization> nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
# ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
#

set -e

ARTIFACT=$1
APP_DIR=$2

WORK_DIR=./upgrading

mkdir -p ${WORK_DIR}

tar xzf ${ARTIFACT} -C ${WORK_DIR}

NEW_ARTIFACT_DIR=`ls ${WORK_DIR}`

if [ -e "${APP_DIR}/current" ]; then
  CURRENT_LINK_DIR=`readlink ${APP_DIR}/current`
  echo "CURRENT APP: ${CURRENT_LINK_DIR}"
  rm -f ${APP_DIR}/current
fi

echo "NEW APP: ${NEW_ARTIFACT_DIR}"

mv ${WORK_DIR}/${NEW_ARTIFACT_DIR} ${APP_DIR}
ln -sf ${NEW_ARTIFACT_DIR} ${APP_DIR}/current

rm -rf ${WORK_DIR}

exit $?