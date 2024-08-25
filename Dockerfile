# Use the official Debian image as a base
FROM debian:latest

# Install necessary dependencies for building Python from source
RUN apt-get update && apt-get install -y \
    wget \
    build-essential \
    libssl-dev \
    zlib1g-dev \
    libbz2-dev \
    libreadline-dev \
    libsqlite3-dev \
    libncurses5-dev \
    libgdbm-dev \
    libnss3-dev \
    libffi-dev \
    liblzma-dev \
    libgmp-dev \
    uuid-dev

# Set the Python version you want to install
ENV PYTHON_VERSION=3.12.5

# Installing cron incase it isn't installed
RUN apt-get install -y cron

# Download and install Python from source
RUN wget https://www.python.org/ftp/python/${PYTHON_VERSION}/Python-${PYTHON_VERSION}.tgz && \
    tar -xvf Python-${PYTHON_VERSION}.tgz && \
    cd Python-${PYTHON_VERSION} && \
    ./configure --enable-optimizations && \
    make -j $(nproc) && \
    make altinstall && \
    cd .. && \
    rm -rf Python-${PYTHON_VERSION} Python-${PYTHON_VERSION}.tgz

# Install python 3.12.5(latest)
RUN wget https://bootstrap.pypa.io/get-pip.py && \
    python3.12 get-pip.py && \
    rm get-pip.py

# Set the working directory inside the container
WORKDIR /app

# Copy the current directory contents into the container at /app while ignoring venv and other stuff
COPY task.py startup.py data_access.py errors.py requirements.txt /app/

#installing requirements.txt
RUN pip3.12 install --no-cache-dir -r requirements.txt

EXPOSE 8000

# Run the Python script with the specific Python version installed
CMD ["python3.12", "task.py"]