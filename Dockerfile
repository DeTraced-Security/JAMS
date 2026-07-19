FROM fedora:latest AS builder

RUN dnf install -y git cmake ninja-build gcc-c++ openssl-devel \
    sqlite-devel liburing-devel && dnf clean all

WORKDIR /src

COPY . .

RUN cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build build


FROM fedora:latest

RUN dnf install -y openssl sqlite sqlite-libs liburing ca-certificates libcap \
     && dnf clean all


# Create runtime user
RUN useradd \
    --system \
    --create-home \
    --home-dir /var/lib/jams \
    --shell /sbin/nologin \
    jams

RUN mkdir -p /etc/jams/tls
RUN openssl req \
  -x509 \
  -newkey rsa:4096 \
  -keyout certs/key.pem \
  -out certs/cert.pem \
  -days 365 \
  -nodes \
  -subj "/CN=mail.detraced.org" # This is an example


# Required directories from documentation
RUN mkdir -p /var/lib/jams /var/mail/vhosts /etc/jams \
    && chown -R jams:jams /var/lib/jams /var/mail/vhosts /etc/jams


COPY --from=builder /src/build/mailserver /usr/local/bin/mailserver

RUN setcap cap_net_bind_service=+ep /usr/local/bin/mailserver

USER jams

EXPOSE 25 587 143 993


ENTRYPOINT ["/usr/local/bin/mailserver"]

CMD ["--db", "/var/lib/jams/users.db"]