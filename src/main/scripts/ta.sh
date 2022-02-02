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
