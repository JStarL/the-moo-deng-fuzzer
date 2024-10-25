# Start from a default Ubuntu image.
FROM ubuntu:22.04

# Update the package list and install Python3 and virtualenv.
RUN apt update && apt upgrade -y && apt install -y \
    python3 \
    python3-venv

# Set the working directory inside the container.
WORKDIR /app

# Copy the entire project directory (including harness.py) to the container.
COPY . /app/

# Ensure that harness.py is executable.
RUN chmod +x /app/harness.py

# Ensure that binaries are executable.
RUN chmod +x /app/binaries/*

# Create a directory for fuzzer outputs, ignore if it already exists.
RUN mkdir -p /app/fuzzer_output

# Run the Python script harness.py when the container starts.
CMD ["python3", "harness.py"]
