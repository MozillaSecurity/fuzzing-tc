FROM python:3.7

COPY . /src

# Setup git for ssh clones
RUN apt-get update -qq && apt-get install -qq git openssh-client
RUN mkdir ~/.ssh && chmod 0600 ~/.ssh && ssh-keyscan github.com > ~/.ssh/known_hosts

RUN pip install --disable-pip-version-check --no-cache-dir --quiet /src

# Setup env variable for tc-admin.py discovery
ENV TC_ADMIN_PY=/src/tc-admin.py

CMD "fuzzing-decision"
