#!/usr/bin/env bash


EXECUTION_DIR=`dirname "$BASH_SOURCE"`
cd ${EXECUTION_DIR}

# Preconditions:
: ${APPLICATION_ENVIRONMENT:?"Please export APPLICATION_ENVIRONMENT"}
: ${JAVA_HOME:?"Please export JAVA_HOME"}

if [[ ! -x "${JAVA_HOME}/bin/java" ]]; then
  echo "${JAVA_HOME}/bin/java not found or not executable, exiting (is JAVA_HOME really a JAVA_HOME?)"
  exit
fi

echo "Running mode APPLICATION_ENVIRONMENT=\"${APPLICATION_ENVIRONMENT}\" with JAVA_HOME=\"${JAVA_HOME}\"" >&2

if [ ${APPLICATION_ENVIRONMENT} == "production" ]; then
    NFAST_BIN=/opt/nfast/bin/
fi

CONF_DIR="conf"
LIB_DIR="lib"
CLASSPATH=${CONF_DIR}:"$LIB_DIR/*"
CARDSET="TA2022"
MAIN_CLASS="net.ripe.rpki.ta.Main"

TA_TOOL_COMMAND="${JAVA_HOME}/bin/java ${JAVA_OPTS} -classpath ${CLASSPATH} ${MAIN_CLASS} --env=${APPLICATION_ENVIRONMENT} $@"

if [ ${APPLICATION_ENVIRONMENT} == "production" ]; then
  # production:
  # * load the JCE provider from the module path
  # * uses cardset protected keys
  JAVA_OPTS="--module-path=/opt/nfast/java/classes -Dprotect=cardset -DignorePassphrase=true $JAVA_OPTS"

  # preload the keys (and provide OCS authorisation with 3/10 cards), then execute the trust anchor binary.
  ${NFAST_BIN}/preload -c ${CARDSET} ${TA_TOOL_COMMAND}
else
  ${TA_TOOL_COMMAND}
fi
