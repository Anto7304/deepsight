FROM python:3.12-slim
WORKDIR /lab
COPY server.py /lab/server.py
RUN useradd -r -u 10001 lab
USER lab
CMD ["python", "server.py"]
