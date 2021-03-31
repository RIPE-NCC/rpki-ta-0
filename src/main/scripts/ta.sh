#!/usr/bin/env bash
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



EXECUTION_DIR=`dirname "$BASH_SOURCE"`
cd ${EXECUTION_DIR}

# Preconditions:
: ${APPLICATION_ENVIRONMENT:?"Please export APPLICATION_ENVIRONMENT"}

echo "Running mode APPLICATION_ENVIRONMENT => ${APPLICATION_ENVIRONMENT}" >&2

if [ ${APPLICATION_ENVIRONMENT} == "production" ]; then
    JAVA_HOME=/export/bad/java
    NFAST_BIN=/opt/nfast/bin/
else
    : ${JAVA_HOME:?"Please export JAVA_HOME"}
fi

CONF_DIR="conf"
LIB_DIR="lib"
CLASSPATH=${CONF_DIR}:"$LIB_DIR/*"
CARDSET="TA"
MAIN_CLASS="net.ripe.rpki.ta.Main"

TA_TOOL_COMMAND="${JAVA_HOME}/bin/java ${JAVA_OPTS} -classpath ${CLASSPATH} ${MAIN_CLASS} --env=${APPLICATION_ENVIRONMENT} $@"

if [ ${APPLICATION_ENVIRONMENT} == "production" ]; then
  #
  # Use HSM =>
  #  - erase passphrase to work around bug that passphrase of last card must be empty
  #  - preload security
  #  - reset passphrase
  JAVA_OPTS="-Dprotect=cardset -DignorePassphrase=true $JAVA_OPTS"

  echo "Set empty passphrase on operator card please (or ctrl+c and start again)"
  ${NFAST_BIN}/cardpp --change

  echo "You have now 10 seconds to remove this card, please do so and use it as the THIRD card in pre-load"
  sleep 10

  ${NFAST_BIN}/preload -c ${CARDSET} ${TA_TOOL_COMMAND}

  echo "Restore passphrase on operator card please"
  ${NFAST_BIN}/cardpp --change

else
  ${TA_TOOL_COMMAND}
fi
