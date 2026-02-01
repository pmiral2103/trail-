# Use official Python image
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Run the AI model training script to ensure .pkl exists
RUN python train_ai_model.py

# Expose port (Hugging Face uses 7860)
EXPOSE 7860

# Command to run the app
CMD ["gunicorn", "--bind", "0.0.0.0:7860", "forensic_api:app"]
