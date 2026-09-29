FROM ghcr.io/zaproxy/zaproxy:stable

USER root
COPY server.py /opt/trovex-scanner/server.py
RUN chmod 0555 /opt/trovex-scanner/server.py

USER zap
ENV PORT=8082
EXPOSE 8082
CMD ["python3", "/opt/trovex-scanner/server.py"]