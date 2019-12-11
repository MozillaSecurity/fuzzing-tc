FROM python:3-slim

COPY . /src

RUN pip install --disable-pip-version-check --no-cache-dir --quiet /src

CMD "fuzzing-decision"
