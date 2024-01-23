#!/usr/bin/env bash

# 
# ====================
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
# 
# Copyright 2008-2009 Sun Microsystems, Inc. All rights reserved.
# 
# The contents of this file are subject to the terms of the Common Development
# and Distribution License("CDDL") (the "License").  You may not use this file
# except in compliance with the License.
# 
# You can obtain a copy of the License at
# http://opensource.org/licenses/cddl1.php
# See the License for the specific language governing permissions and limitations
# under the License.
# 
# When distributing the Covered Code, include this CDDL Header Notice in each file
# and include the License file at http://opensource.org/licenses/cddl1.php.
# If applicable, add the following below this CDDL Header, with the fields
# enclosed by brackets [] replaced by your own identifying information:
# "Portions Copyrighted [year] [name of copyright owner]"
# ====================
# Portions Copyrighted 2011 ConnId.
# 

cd /opt/opendj

sh ./bin/makeldif --outputLdif /opt/opendj/bootstrap/data/bigcompany.ldif /opt/opendj/bootstrap/bigcompany.template
chmod 777 /opt/opendj/bootstrap/data/bigcompany.ldif

#if defaul data folder exists do not change it
if [ ! -d ./db ] ; then
  echo "/opt/opendj/data" > /opt/opendj/instance.loc  && \
    mkdir -p /opt/opendj/data/lib/extensions
fi

# Instance dir does not exist? Then we need to run setup
if [ ! -d ./data/config ] ; then

  echo "Instance data Directory is empty. Creating new DJ instance"

  BOOTSTRAP=${BOOTSTRAP:-/opt/opendj/bootstrap/setup.sh}

  export BASE_DN=${BASE_DN:-"dc=example,dc=com"}
  echo "BASE DN is ${BASE_DN}"

  export PASSWORD=${ROOT_PASSWORD:-password}

  echo "Password set to $PASSWORD"

  echo "Running $BOOTSTRAP"
  sh "${BOOTSTRAP}"

  # Check if OPENDJ_REPLICATION_TYPE var is set. If it is - replicate to that server
  if [ ! -z ${MASTER_SERVER} ] && [ ! -z ${OPENDJ_REPLICATION_TYPE} ];  then
    /opt/opendj/bootstrap/replicate.sh
  fi

  # Check if CHANGELOG var is set. If it is - enable changelog to that server
  if [ ! -z ${CHANGELOG} ];  then
    /opt/opendj/bootstrap/changelog.sh
  fi

else
 sh ./upgrade -n
 exec ./bin/start-ds --nodetach
 return
fi

# Check if keystores are mounted as a volume, and if so
# Copy any keystores over
SECRET_VOLUME=${SECRET_VOLUME:-/var/secrets/opendj}

if [ -d "${SECRET_VOLUME}" ]; then
  echo "Secret volume is present. Will copy any keystores and truststore"
  # We send errors to /dev/null in case no data exists.
  cp -f ${SECRET_VOLUME}/key*   ${SECRET_VOLUME}/trust* ./data/config 2>/dev/null
fi

sh ./bin/dsconfig set-access-control-handler-prop -h localhost -p 4444 -D "cn=Directory Manager" -w password -n -X \
   --add global-aci:"(targetattr=\"userPassword||authPassword||debugsearchindex||changes||changeNumber||changeType||changeTime||targetDN||newRDN||newSuperior||deleteOldRDN\")(version 3.0; acl \"Anonymous read access\"; allow (read,search,compare) userdn=\"ldap:///uid=admin,dc=example,dc=com\";)"

sh ./bin/dsconfig -h localhost -p 4444 -D "cn=Directory Manager" -w password -n -X create-backend-vlv-index \
    --backend-name userRoot --index-name index-uid --set sort-order:uid --set scope:whole-subtree \
    --set base-dn:dc=example,dc=com --set filter:"(&(objectClass=inetOrgPerson)(objectClass=organizationalPerson)(objectClass=person)(objectClass=top))"

sh ./bin/rebuild-index --baseDN "dc=example,dc=com" --bindPassword password -X --index vlv.index-uid

# Run upgrade if the server is older

if (bin/status -n | grep Started) ; then
   echo "OpenDJ is started"
   # We cant exit because we are pid 1
   while true; do sleep 100000; done
fi

echo "Try to upgrade OpenDJ"
sh ./upgrade -n

echo "Starting OpenDJ"
exec ./bin/start-ds --nodetach
