FROM python:3.12-slim
WORKDIR /app
COPY server.py .
RUN pip install flask
EXPOSE 9876
CMD ["python", "server.py"]
