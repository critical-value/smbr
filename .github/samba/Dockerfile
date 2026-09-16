FROM debian:bookworm-slim

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update \
    && apt-get install --no-install-recommends -y samba \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --shell /usr/sbin/nologin smbr \
    && mkdir -p /srv/share \
    && chown -R smbr:smbr /srv/share \
    && (echo 'smbrpass'; echo 'smbrpass') | smbpasswd -a -s smbr

COPY smb.conf /etc/samba/smb.conf

EXPOSE 139 445
CMD ["smbd", "--foreground", "--no-process-group", "--debug-stdout", "-s", "/etc/samba/smb.conf"]
