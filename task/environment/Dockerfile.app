FROM bkimminich/juice-shop@sha256:42843723a7bf4246aa5d63c324978b17ef296ac78434aeddd34c427bfb5853f4
USER 0
COPY disable-restore.cjs /opt/benchmark/disable-restore.cjs
RUN ["/nodejs/bin/node", "/opt/benchmark/disable-restore.cjs"]
USER 65532
