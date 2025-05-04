# Step 1: Use Python as the base image
FROM python:3.9-slim

# Step 2: Set the working directory
WORKDIR /app

# Step 3: Install system dependencies
RUN apt-get update && apt-get install -y \
    python3-dev \
    && pip install --no-cache-dir --upgrade pip

# Step 4: Copy the requirements file for Python dependencies
COPY requirements.txt /app/

# Step 5: Install the Python dependencies
RUN pip install -r requirements.txt

# Step 6: Copy the web application code into the container
COPY . /app/

# Step 7: Expose the port (Flask defaults to port 5000)
EXPOSE 5000

# Step 8: Run the Flask web server
CMD ["python", "app.py"]
