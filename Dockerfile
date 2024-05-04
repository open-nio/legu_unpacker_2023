FROM debian:bookworm-20240423-slim

RUN apt update
RUN apt install -y python3 \
    python3-dev \
    python3-venv \
    python3-pip \
    libucl-dev \
    git

RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

WORKDIR /opt
RUN git clone https://github.com/lcsfelix/pyucl.git
WORKDIR /opt/pyucl
RUN pip install -r requirements.txt
RUN python setup.py build
RUN python setup.py install


WORKDIR /unpacker
COPY . .
RUN pip install -r requirements.txt
