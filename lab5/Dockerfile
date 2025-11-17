ARG UBUNTU_VERSION=22.04
FROM ubuntu:${UBUNTU_VERSION}

ARG ROLE=CLIENTE
ENV ROLE=${ROLE}
ENV DEBIAN_FRONTEND=noninteractive

RUN sed -i 's/archive.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list || true && \
    sed -i 's/security.ubuntu.com/old-releases.ubuntu.com/g' /etc/apt/sources.list || true

RUN apt-get update && apt-get install -y \
    openssh-client \
    openssh-server \
    iproute2 \
    vim \
    net-tools && \
    mkdir -p /var/run/sshd && \
    rm -rf /var/lib/apt/lists/*

RUN if [ "$ROLE" = "SERVIDOR" ]; then \
      echo 'root:root' | chpasswd && \
      sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config && \
      sed -i 's@session\\s*required\\s*pam_loginuid.so@session optional pam_loginuid.so@g' /etc/pam.d/sshd && \
      mkdir -p /root/.ssh; \
    fi

EXPOSE 22

CMD if [ "$ROLE" = "SERVIDOR" ]; then \
      echo "Iniciando servidor" ; \
      /usr/sbin/sshd -D; \
    else \
      echo "Contenedor cliente"; \
      exec bash; \
    fi
