FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN useradd -r -u 10001 sim
COPY sim.py /sim.py
USER sim
CMD ["python", "/sim.py"]
