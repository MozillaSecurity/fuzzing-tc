FROM python:3.7

# Setup git for ssh clones
RUN apt-get update -qq && apt-get install --no-install-recommends -qq git openssh-client && rm -rf /var/lib/apt/lists/*
RUN mkdir ~/.ssh && chmod 0600 ~/.ssh && ssh-keyscan github.com > ~/.ssh/known_hosts

COPY . /src

RUN pip install --disable-pip-version-check --no-cache-dir --quiet /src[decision]

# Setup env variable for tc-admin.py discovery
ENV TC_ADMIN_PY=/src/tc-admin.py

CMD "fuzzing-decision"
