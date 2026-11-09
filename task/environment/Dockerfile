FROM python@sha256:9662417aace5ae7b8e2609cce472b72a8958e134ba372808abe9cc1a0c0125e6
RUN ["python", "-c", "import os; os.makedirs('/work', exist_ok=True); os.chown('/work', 65532, 65532)"]
WORKDIR /work
USER 65532:65532
