# Use official Python slim image
FROM python:3.11-slim

# Set working directory in container
WORKDIR /app

# Copy requirements and install them
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy all project files into the container
COPY . .

# Expose port 3244 for the Flask app
EXPOSE 3244

# Command to run the Flask app
CMD ["python", "oracle_api.py"]
