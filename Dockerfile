FROM python:3.11-slim
WORKDIR /netwatch
COPY install ./install
COPY src ./
RUN cd install && chmod +x setup.sh && ./setup.sh && cd ..
EXPOSE 8503
EXPOSE 8504
CMD ["python3", "main.py"]