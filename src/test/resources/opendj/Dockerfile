# 
# ====================
# DO NOT ALTER OR REMOVE COPYRIGHT NOTICES OR THIS HEADER.
# 
# Copyright 2011 ConnId. All rights reserved.
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
# 

FROM openidentityplatform/opendj:4.6.2

USER root

RUN mkdir -p /opt/opendj/bootstrap/data
ADD config-additions.ldif /opt/opendj/bootstrap/data
ADD data.ldif /opt/opendj/bootstrap/data
ADD admin.ldif /opt/opendj/bootstrap/data
RUN chmod -R 777 /opt/opendj/bootstrap/data

ADD bigcompany.template /opt/opendj/bootstrap

ADD run.sh /opt/opendj/run.sh

RUN chgrp -R 0 /opt/opendj && \
    chmod -R g=u /opt/opendj && \
    chmod +x /opt/opendj/run.sh

USER $OPENDJ_USER
ENTRYPOINT ["/opt/opendj/run.sh"]
