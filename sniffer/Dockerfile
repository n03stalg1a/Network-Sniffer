# Step 1: Use a Python base image (Python 3.9)
FROM python:3.9-slim

# Step 2: Set the working directory inside the container
WORKDIR /app

# Step 3: Install system dependencies
RUN apt-get update && apt-get install -y \
    python3-dev \
    libpq-dev \
    build-essential \
    && pip install --no-cache-dir --upgrade pip

# Step 4: Copy the requirements file for Python dependencies
COPY requirements.txt /app/

# Step 5: Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Step 6: Copy all application code (sniffer) into the container
COPY . /app/

# Step 7: Set environment variables (Kafka and DB server)
ENV KAFKA_SERVER=kafka:9092
ENV DB_HOST=db

# Step 8: Run the sniffer script (change to the appropriate file)
CMD ["python", "sniffer.py"]
