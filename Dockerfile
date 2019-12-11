FROM python:3-slim

COPY . /src

# Setup git for ssh clones
RUN apt-get update -qq && apt-get install -qq git openssh-client
RUN mkdir ~/.ssh && chmod 0600 ~/.ssh && ssh-keyscan github.com > ~/.ssh/known_hosts

RUN pip install --disable-pip-version-check --no-cache-dir --quiet /src

CMD "fuzzing-decision"
